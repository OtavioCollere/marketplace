import { Logger } from "@nestjs/common";

export class CacheFallBackService{
  private readonly logger = new Logger(CacheFallBackService.name);
  private readonly cache = new Map<string, {data : any, timestamp : number}>();

  async getCacheData<T>(key: string, timeout: number = 30000): Promise<T | null> {
   const cached = await this.cache.get(key);
   
   if(!cached) {
    return null;
   }

   const isExpired = Date.now() - cached.timestamp > timeout;
   if(isExpired) {
    this.cache.delete(key);
    return null;
   }

   this.logger.log(`Cache hit for key: ${key}`);
   return cached.data;
  }
  
  async setCacheData<T>(key: string, data: T, timeout: number = 30000): Promise<void> {
    this.cache.set(key, {data, timestamp: Date.now()});
    this.logger.log(`Cache set for key: ${key}`);
  }

  createCacheFallback<T>(key: string, defaultData : T, timeout: number = 30000): () => Promise<T> {
    return async () => {
      const cached = await this.getCacheData<T>(key, timeout);

      if(cached) {
        this.logger.log(`Cache fallback for key: ${key}`);
        return cached;
      }

      this.logger.warn(`Cache miss for key: ${key}, using fallback`);
      return defaultData;
    };
  }
}