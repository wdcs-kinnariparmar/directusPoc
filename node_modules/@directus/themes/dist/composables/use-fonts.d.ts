import { Theme } from '../schemas/theme.js';
import { MaybeRef } from 'vue';

export declare const useFonts: (theme: MaybeRef<Theme>) => {
    googleFonts: import('vue').ComputedRef<string[]>;
};
