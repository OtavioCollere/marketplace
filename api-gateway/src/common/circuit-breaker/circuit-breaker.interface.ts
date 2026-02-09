export  interface CircuitBreakerOptions{
  failureThreshold : number; // numero maximo de falhas para ativar o circuit breaker
  timeout : number; // tempo de espera para definir que é uma falha
  resetTimeout : number; // tempo que deve permanecer em estado aberto para resetar o circuit breaker
}

export enum CircuitBreakerStateEnum{
  CLOSED = 'closed',
  OPEN = 'open',
  HALF_OPEN = 'half-open',
}

export interface CircuitBreakerState{
  state : CircuitBreakerStateEnum;
  failureCount : number;
  lastFailureTime : Date;
  nextAttemptTime : Date;
}

export interface CircuitBreakerResult<T> {
  success : boolean;
  data? : T;
  error? : Error;
  fromCache? : boolean;
}