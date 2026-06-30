interface ImportMetaEnv {
  readonly VITE_INDEXER_URL?: string;
  readonly VITE_INDEXER_IDENTITY?: string;
  readonly VITE_INDEXER_PARTICIPANTS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
