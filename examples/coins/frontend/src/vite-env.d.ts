interface ImportMetaEnv {
  readonly VITE_INDEXER_URL?: string;
  readonly VITE_APP_TITLE?: string;
  readonly VITE_APP_SUBTITLE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
