import { Injectable, Logger } from "@nestjs/common";
import { CircuitBreakerStateEnum, type CircuitBreakerOptions, type CircuitBreakerState } from "./circuit-breaker.interface";

@Injectable()
export class CircuitBreakerService {
  private readonly logger : Logger = new Logger(CircuitBreakerService.name);
  private readonly circuits = new Map<string, CircuitBreakerState>();
  private readonly defaultOptions : CircuitBreakerOptions = {
    failureThreshold : 5,
    timeout : 60000, // 1 minute
    resetTimeout : 30000, // 30 seconds
  }

  async executeWithCircuitBreaker<T>(
    operation: () => Promise<T>,
    key : string,
    fallback? : () => Promise<T>,
    options : CircuitBreakerOptions = this.defaultOptions
  ) {
    
    const config = {...this.defaultOptions, ...options};
    const circuit = this.getOrCreateCircuit(key, config);
    
    if (!circuit) {
      throw new Error(`Failed to create circuit for key: ${key}`);
    }
    
    if(circuit.state === CircuitBreakerStateEnum.OPEN) {
      
      if(Date.now() < circuit.nextAttemptTime.getTime()) {
        this.logger.warn(`Circuit ${key} is in OPEN state. Waiting for next attempt.`);
        if(fallback) {
          return fallback();
        }
        throw new Error('Circuit breaker OPEN');
      } else {
        circuit.state = CircuitBreakerStateEnum.HALF_OPEN;
        this.logger.warn(`Circuit ${key} is in HALF_OPEN state. Attempting to recover.`);
      }

    }

    try{
      const result = await operation();
      this.onSuccess(circuit, key);
      return result;
    } catch (error) {
      this.onFailure(circuit, key, error, config);
      this.logger.error(`Circuit ${key} failed. Error: ${error.message}`);
      if(fallback) {
        return fallback();
      }
      throw error;
    }

  }

  private getOrCreateCircuit(key : string, config : CircuitBreakerOptions) {
    if( !this.circuits.has(key)) {
      this.circuits.set(key, {
        state : CircuitBreakerStateEnum.CLOSED,
        failureCount : 0,
        lastFailureTime : new Date(0),
        nextAttemptTime : new Date(0),
      });
    }
    return this.circuits.get(key);
  }

  private onSuccess(circuit : CircuitBreakerState, key : string) {
    circuit.state = CircuitBreakerStateEnum.CLOSED;
    circuit.failureCount = 0;
    circuit.lastFailureTime = new Date(0);
    circuit.nextAttemptTime = new Date(0);
    this.logger.log(`Circuit ${key} is in CLOSED state. Successfully executed operation.`);
  }

  private onFailure(circuit : CircuitBreakerState, key : string, error : Error, config : CircuitBreakerOptions) {
    circuit.failureCount++;
    circuit.lastFailureTime = new Date();
    if(circuit.failureCount >= config.failureThreshold) {
      circuit.state = CircuitBreakerStateEnum.OPEN;
      circuit.nextAttemptTime = new Date(Date.now() + config.resetTimeout);
      this.logger.warn(`Circuit ${key} is in OPEN state. Failure threshold reached. Resetting in ${config.resetTimeout}ms.`);
    }
  }

  getCircuitState(key: string) {
    return this.circuits.get(key);
  }

  getAllCircuits() : Map<string, CircuitBreakerState> {
    return new Map(this.circuits);
  }

  resetCircuit(key: string) {
    this.circuits.delete(key);
    this.logger.log(`Circuit ${key} has been reset.`);
  }
}
