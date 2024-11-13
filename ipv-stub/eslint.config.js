const typescriptEslint = require("@typescript-eslint/eslint-plugin");
const globals = require("globals");
const parser = require("@typescript-eslint/parser");
const { FlatCompat } = require("@eslint/eslintrc");
const js = require("@eslint/js");
const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
});

module.exports = [
    ...compat.extends("plugin:@typescript-eslint/recommended"),
    {
        plugins: {
            "@typescript-eslint": typescriptEslint,
        },
    },
    {
        files: ["**/*.ts", "**/*.js"],
        languageOptions: {
            parser: parser,
            ecmaVersion: 2020,
            sourceType: "module",
            globals: {
                ...globals.node,
            },
        },
        rules: {
            "@typescript-eslint/no-unused-vars": [
                "error",
                {
                    argsIgnorePattern: "^_",
                    varsIgnorePattern: "^_",
                    caughtErrorsIgnorePattern: "^_",
                },
            ],
        },
        linterOptions: {
            reportUnusedDisableDirectives: true,
        },
    },
    {
        ignores: [
            "eslint.config.js",
        ],
    },
];