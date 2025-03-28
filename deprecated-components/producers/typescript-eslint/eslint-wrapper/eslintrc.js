module.exports = {
  env: {
    browser: true,
    es2021: true,
  },
  extends: [
    "plugin:security/recommended",
    "plugin:xss/recommended",
    "plugin:no-unsanitized/DOM",
    "plugin:security-node/recommended",
  ],
  overrides: [],
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
  },
  plugins: [],
  rules: {},
};
