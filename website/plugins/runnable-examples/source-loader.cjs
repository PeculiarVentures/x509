// Compiles the library source with the root tsconfig, as the published build does:
// legacy decorators for tsyringe, and class fields set by assignment
// (`useDefineForClassFields: false`), so subclass fields filled by `onInit()` keep their values.
const path = require("node:path");
const ts = require("typescript");

const rootTsconfig = path.resolve(__dirname, "../../../tsconfig.json");

let compilerOptions;

function getCompilerOptions() {
  if (!compilerOptions) {
    const { config, error } = ts.readConfigFile(rootTsconfig, ts.sys.readFile);
    if (error) {
      throw new Error(ts.flattenDiagnosticMessageText(error.messageText, "\n"));
    }
    const { options } = ts.convertCompilerOptionsFromJson(config.compilerOptions, path.dirname(rootTsconfig));
    compilerOptions = { ...options, noEmit: false, sourceMap: false, module: ts.ModuleKind.ESNext };
  }
  return compilerOptions;
}

module.exports = function sourceLoader(source) {
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: getCompilerOptions(),
    fileName: this.resourcePath,
  });
  return outputText;
};
