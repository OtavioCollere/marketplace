import { Module } from '@nestjs/common';
import { ProxyService } from './service/proxy.service';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports : [
    HttpModule.register({}),
  ],
  providers: [ProxyService],
  exports: [ProxyService]
})
export class ProxyModule {}
