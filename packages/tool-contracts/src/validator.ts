import { ToolParameterSchema } from '@lucifer/shared-types';

export class ToolValidator {
  /**
   * Validates tool input arguments against its parameter schema
   */
  public static validate(schema: ToolParameterSchema, args: Record<string, unknown>): { valid: boolean; error?: string } {
    if (!schema || schema.type !== 'object') {
      return { valid: true };
    }

    if (schema.required) {
      for (const requiredProp of schema.required) {
        if (args[requiredProp] === undefined || args[requiredProp] === null || args[requiredProp] === '') {
          return { valid: false, error: `Missing required argument: '${requiredProp}'` };
        }
      }
    }

    if (schema.properties) {
      for (const [key, propDef] of Object.entries(schema.properties)) {
        const val = args[key];
        if (val !== undefined && val !== null) {
          if (propDef.type === 'string' && typeof val !== 'string') {
            return { valid: false, error: `Argument '${key}' must be a string` };
          }
          if (propDef.type === 'number' && typeof val !== 'number') {
            return { valid: false, error: `Argument '${key}' must be a number` };
          }
          if (propDef.type === 'boolean' && typeof val !== 'boolean') {
            return { valid: false, error: `Argument '${key}' must be a boolean` };
          }
          if (propDef.enum && !propDef.enum.includes(String(val))) {
            return { valid: false, error: `Argument '${key}' must be one of: ${propDef.enum.join(', ')}` };
          }
        }
      }
    }

    return { valid: true };
  }
}
