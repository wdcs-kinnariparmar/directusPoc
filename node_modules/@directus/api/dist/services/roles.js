import { ForbiddenError, InvalidPayloadError, UnprocessableContentError } from '@directus/errors';
import { getMatch } from 'ip-matching';
import { transaction } from '../utils/transaction.js';
import { ItemsService } from './items.js';
import { PermissionsService } from './permissions/index.js';
import { PresetsService } from './presets.js';
import { UsersService } from './users.js';
export class RolesService extends ItemsService {
    constructor(options) {
        super('directus_roles', options);
    }
    async checkForOtherAdminRoles(excludeKeys) {
        // Make sure there's at least one admin role left after this deletion is done
        const otherAdminRoles = await this.knex
            .count('*', { as: 'count' })
            .from('directus_roles')
            .whereNotIn('id', excludeKeys)
            .andWhere({ admin_access: true })
            .first();
        const otherAdminRolesCount = Number(otherAdminRoles?.count ?? 0);
        if (otherAdminRolesCount === 0) {
            throw new UnprocessableContentError({ reason: `You can't delete the last admin role` });
        }
    }
    async checkForOtherAdminUsers(key, users) {
        const role = await this.knex.select('admin_access').from('directus_roles').where('id', '=', key).first();
        if (!role)
            throw new ForbiddenError();
        const usersBefore = (await this.knex.select('id').from('directus_users').where('role', '=', key)).map((user) => user.id);
        const usersAdded = [];
        const usersUpdated = [];
        const usersCreated = [];
        const usersRemoved = [];
        if (Array.isArray(users)) {
            const usersKept = [];
            for (const user of users) {
                if (typeof user === 'string') {
                    if (usersBefore.includes(user)) {
                        usersKept.push(user);
                    }
                    else {
                        usersAdded.push({ id: user });
                    }
                }
                else if (user.id) {
                    if (usersBefore.includes(user.id)) {
                        usersKept.push(user.id);
                        usersUpdated.push(user);
                    }
                    else {
                        usersAdded.push(user);
                    }
                }
                else {
                    usersCreated.push(user);
                }
            }
            usersRemoved.push(...usersBefore.filter((user) => !usersKept.includes(user)));
        }
        else {
            for (const user of users.update) {
                if (usersBefore.includes(user['id'])) {
                    usersUpdated.push(user);
                }
                else {
                    usersAdded.push(user);
                }
            }
            usersCreated.push(...users.create);
            usersRemoved.push(...users.delete);
        }
        if (role.admin_access === false || role.admin_access === 0) {
            // Admin users might have moved in from other role, thus becoming non-admin
            if (usersAdded.length > 0) {
                const otherAdminUsers = await this.knex
                    .count('*', { as: 'count' })
                    .from('directus_users')
                    .leftJoin('directus_roles', 'directus_users.role', 'directus_roles.id')
                    .whereNotIn('directus_users.id', usersAdded.map((user) => user.id))
                    .andWhere({ 'directus_roles.admin_access': true, status: 'active' })
                    .first();
                const otherAdminUsersCount = Number(otherAdminUsers?.count ?? 0);
                if (otherAdminUsersCount === 0) {
                    throw new UnprocessableContentError({ reason: `You can't remove the last admin user from the admin role` });
                }
            }
            return;
        }
        // Only added or created new users
        if (usersUpdated.length === 0 && usersRemoved.length === 0)
            return;
        // Active admin user(s) about to be created
        if (usersCreated.some((user) => !('status' in user) || user.status === 'active'))
            return;
        const usersDeactivated = [...usersAdded, ...usersUpdated]
            .filter((user) => 'status' in user && user.status !== 'active')
            .map((user) => user.id);
        const usersAddedNonDeactivated = usersAdded
            .filter((user) => !usersDeactivated.includes(user.id))
            .map((user) => user.id);
        // Active user(s) about to become admin
        if (usersAddedNonDeactivated.length > 0) {
            const userCount = await this.knex
                .count('*', { as: 'count' })
                .from('directus_users')
                .whereIn('id', usersAddedNonDeactivated)
                .andWhere({ status: 'active' })
                .first();
            if (Number(userCount?.count ?? 0) > 0) {
                return;
            }
        }
        const otherAdminUsers = await this.knex
            .count('*', { as: 'count' })
            .from('directus_users')
            .leftJoin('directus_roles', 'directus_users.role', 'directus_roles.id')
            .whereNotIn('directus_users.id', [...usersDeactivated, ...usersRemoved])
            .andWhere({ 'directus_roles.admin_access': true, status: 'active' })
            .first();
        const otherAdminUsersCount = Number(otherAdminUsers?.count ?? 0);
        if (otherAdminUsersCount === 0) {
            throw new UnprocessableContentError({ reason: `You can't remove the last admin user from the admin role` });
        }
        return;
    }
    isIpAccessValid(value) {
        if (value === undefined)
            return false;
        if (value === null)
            return true;
        if (Array.isArray(value) && value.length === 0)
            return true;
        for (const ip of value) {
            if (typeof ip !== 'string' || ip.includes('*'))
                return false;
            try {
                const match = getMatch(ip);
                if (match.type == 'IPMask')
                    return false;
            }
            catch {
                return false;
            }
        }
        return true;
    }
    assertValidIpAccess(partialItem) {
        if ('ip_access' in partialItem && !this.isIpAccessValid(partialItem['ip_access'])) {
            throw new InvalidPayloadError({
                reason: 'IP Access contains an incorrect value. Valid values are: IP addresses, IP ranges and CIDR blocks',
            });
        }
    }
    async createOne(data, opts) {
        this.assertValidIpAccess(data);
        return super.createOne(data, opts);
    }
    async createMany(data, opts) {
        for (const partialItem of data) {
            this.assertValidIpAccess(partialItem);
        }
        return super.createMany(data, opts);
    }
    async updateOne(key, data, opts) {
        this.assertValidIpAccess(data);
        try {
            if ('users' in data) {
                await this.checkForOtherAdminUsers(key, data['users']);
            }
        }
        catch (err) {
            (opts || (opts = {})).preMutationError = err;
        }
        return super.updateOne(key, data, opts);
    }
    async updateBatch(data, opts) {
        for (const partialItem of data) {
            this.assertValidIpAccess(partialItem);
        }
        const primaryKeyField = this.schema.collections[this.collection].primary;
        const keys = data.map((item) => item[primaryKeyField]);
        const setsToNoAdmin = data.some((item) => item['admin_access'] === false);
        try {
            if (setsToNoAdmin) {
                await this.checkForOtherAdminRoles(keys);
            }
        }
        catch (err) {
            (opts || (opts = {})).preMutationError = err;
        }
        return super.updateBatch(data, opts);
    }
    async updateMany(keys, data, opts) {
        this.assertValidIpAccess(data);
        try {
            if ('admin_access' in data && data['admin_access'] === false) {
                await this.checkForOtherAdminRoles(keys);
            }
        }
        catch (err) {
            (opts || (opts = {})).preMutationError = err;
        }
        return super.updateMany(keys, data, opts);
    }
    async updateByQuery(query, data, opts) {
        this.assertValidIpAccess(data);
        return super.updateByQuery(query, data, opts);
    }
    async deleteOne(key) {
        await this.deleteMany([key]);
        return key;
    }
    async deleteMany(keys) {
        const opts = {};
        try {
            await this.checkForOtherAdminRoles(keys);
        }
        catch (err) {
            opts.preMutationError = err;
        }
        await transaction(this.knex, async (trx) => {
            const itemsService = new ItemsService('directus_roles', {
                knex: trx,
                accountability: this.accountability,
                schema: this.schema,
            });
            const permissionsService = new PermissionsService({
                knex: trx,
                accountability: this.accountability,
                schema: this.schema,
            });
            const presetsService = new PresetsService({
                knex: trx,
                accountability: this.accountability,
                schema: this.schema,
            });
            const usersService = new UsersService({
                knex: trx,
                accountability: this.accountability,
                schema: this.schema,
            });
            // Delete permissions/presets for this role, suspend all remaining users in role
            await permissionsService.deleteByQuery({
                filter: { role: { _in: keys } },
            }, { ...opts, bypassLimits: true });
            await presetsService.deleteByQuery({
                filter: { role: { _in: keys } },
            }, { ...opts, bypassLimits: true });
            await usersService.updateByQuery({
                filter: { role: { _in: keys } },
            }, {
                status: 'suspended',
                role: null,
            }, { ...opts, bypassLimits: true });
            await itemsService.deleteMany(keys, opts);
        });
        return keys;
    }
    deleteByQuery(query, opts) {
        return super.deleteByQuery(query, opts);
    }
}
