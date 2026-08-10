import typescriptEslint from "@typescript-eslint/eslint-plugin";
import globals from "globals";
import parser from "@typescript-eslint/parser";
import { FlatCompat } from "@eslint/eslintrc";
import js from "@eslint/js";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
});

export default [
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
            ".aws-sam/",
            "build/"
        ],
    },
];
