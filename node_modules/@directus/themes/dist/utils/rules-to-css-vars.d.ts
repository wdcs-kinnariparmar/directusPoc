import { Theme } from '../schemas/index.js';
import { DeepPartial } from '@directus/types';

export declare const rulesToCssVars: (rules: DeepPartial<Theme['rules']>) => Record<string, string | number>;
