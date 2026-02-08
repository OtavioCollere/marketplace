import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { LoggingMiddleware } from './logging/logging.middleware';

@Module({
  imports : [

  ],
  providers : [
    LoggingMiddleware,
  ]
})
export class MiddlewareModule {}
