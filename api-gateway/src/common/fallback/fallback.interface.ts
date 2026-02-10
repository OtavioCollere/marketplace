
export interface FallbackStrategy<T> {
  execute() : Promise<T>;
}

export interface FallbackOptions {
  useCache?: boolean;
  cacheTimeout?: number;
  defaultResponse : unknown;
  retryCount?: number;
  retryDelay?: number;
}

