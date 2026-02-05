/**
 * ShadowHawk Platform Utility Helpers
 */
import { clsx, type ClassValue } from "clsx";

export const cn = (...inputs: ClassValue[]) => clsx(inputs);
