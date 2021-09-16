module.exports = {
    preset: 'react-native',
    transform: {'^.+\\.(ts|tsx)?$': 'ts-jest', '^.+\\.js$': '<rootDir>/node_modules/react-native/jest/preprocessor.js'},
    testEnvironment: 'node',
    testRegex: '/test/.*\\.(test|spec)?\\.(js|jsx|tsx)$',
    moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
};
