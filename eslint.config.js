import js from '@eslint/js';
import globals from 'globals';

export default [
	{
		ignores: [
			'node_modules/',
			'generated/',
			'target/',
			'workers/kofra-api/build/',
			'workers/kofra-api/.wrangler/'
		]
	},
	js.configs.recommended,
	{
		languageOptions: { ecmaVersion: 'latest', sourceType: 'module', globals: { ...globals.node } }
	},
	// Worker modules run on the Workers runtime (service-worker globals).
	{
		files: ['workers/kofra-api/entry.mjs', 'workers/kofra-api/e2e/caller.mjs'],
		languageOptions: { globals: { ...globals.serviceworker } }
	}
];
