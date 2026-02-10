import { Module } from "@nestjs/common";
import { CacheFallBackService } from "./cache.fallback";
import { DefaultFallbackService } from "./default.fallback";

@Module({
  providers : [CacheFallBackService, DefaultFallbackService],
  exports : [CacheFallBackService, DefaultFallbackService]
})
export class FallbackModule {}