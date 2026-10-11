/// <reference types="vite/client" />

// The vendored probe WASM, imported as a URL asset (Vite `?url`). Passed to the
// SDK's `initProbe(url)` so wasm loading does not rely on `import.meta.url`.
declare module '@cdlab/fingerprintd/wasm?url' {
  const src: string
  export default src
}
