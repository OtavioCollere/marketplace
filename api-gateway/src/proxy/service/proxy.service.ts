import { HttpService } from '@nestjs/axios';
import type { AxiosResponse } from 'axios';
import { Injectable, Logger } from '@nestjs/common';
import { firstValueFrom } from 'rxjs';
import { serviceConfig } from 'src/config/gateway.config';


@Injectable()
export class ProxyService {
  private readonly logger = new Logger(ProxyService.name);

  constructor(
    private readonly httpService: HttpService,
  ) {}

  // Proxy the request to the service
  async proxyRequest(
    serviceName : keyof typeof serviceConfig,
    method : string,
    path : string,
    data?: any,
    headers? : any,
    userInfo? : any
  ): Promise<AxiosResponse> {
    const service = serviceConfig[serviceName];
    const url = `${service.url}${path}`;
    
    this.logger.log(`Proxying method ${method} to ${serviceName} service at ${url}`);
  
    try{
      const enhancedHeaders = {
        ...headers,
        'x-user-id' : userInfo?.id,
        'x-user-email' : userInfo?.email,
        'x-user-role' : userInfo?.role,
      }

      const response = await firstValueFrom(
        this.httpService.request({
          method: method.toLowerCase(),
          url,
          data,
          headers: enhancedHeaders,
          timeout: service.timeout,
        })
      )

      return response
    } catch (error) {
      this.logger.error(`Error proxying request to ${serviceName} service: ${error.message}`);
      throw error;
    }
  
  }

  async getServiceHealth( serviceName : keyof typeof serviceConfig) {
    try{
      const service = serviceConfig[serviceName];
      const response = await firstValueFrom(
        this.httpService.get(`${service.url}/health`, {
          timeout : 3000
        })
      )

      return { status : 'healthy', data : response.data}

    } catch (error) {
      return { status : 'unhealthy', error : error.message}
    }
  }
}
