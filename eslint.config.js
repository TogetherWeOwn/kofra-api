import js from '@eslint/js';
import globals from 'globals';

export default [
	{ ignores: ['node_modules/', 'generated/', 'target/'] },
	js.configs.recommended,
	{
		languageOptions: { ecmaVersion: 'latest', sourceType: 'module', globals: { ...globals.node } }
	}
];
