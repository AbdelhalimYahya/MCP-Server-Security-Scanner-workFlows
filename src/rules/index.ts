import type { Rule } from '../types.js';
import { plaintextSecretsRule } from './plaintextSecrets.js';
import { insecureBindingRule } from './insecureBinding.js';
import { broadPermissionsRule } from './broadPermissions.js';
import { toolDescriptionInjectionRule } from './toolDescriptionInjection.js';
import { missingAuthRule } from './missingAuth.js';
import { vulnerableDependenciesRule } from './vulnerableDependencies.js';

const builtinRules: Rule[] = [
  plaintextSecretsRule,
  insecureBindingRule,
  broadPermissionsRule,
  toolDescriptionInjectionRule,
  missingAuthRule,
  vulnerableDependenciesRule,
];

export function getBuiltinRules(): Rule[] {
  return [...builtinRules];
}
