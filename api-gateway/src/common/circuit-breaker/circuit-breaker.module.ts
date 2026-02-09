import { Module } from "@nestjs/common";
import { CircuitBreakerService } from "./circuit-breaker.service";
import { HttpModule } from "@nestjs/axios";

@Module({
  imports : [],
  providers : [CircuitBreakerService],
  exports : [CircuitBreakerService],
})
export class CircuitBreakerModule {}