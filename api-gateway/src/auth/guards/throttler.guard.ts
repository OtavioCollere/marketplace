import type { ExecutionContext } from "@nestjs/common";
import { ThrottlerException, ThrottlerGuard, type ThrottlerRequest } from "@nestjs/throttler";

export class CustomThrottlerGuard extends ThrottlerGuard {
  protected getTracker(req: Record<string, any>): Promise<string> {
    return Promise.resolve(`${req.ip}-${req.headers['user-agent']}`);
  }

  protected async handleRequest(requestProps : ThrottlerRequest): Promise<boolean> {
    const {context, ttl, limit} = requestProps;

    const {req, res} = await this.getRequestResponse(context);
    const throttles = this.reflector.get('throttle', context.getHandler())
    const throttleName = throttles ? Object.keys(throttles)[0] : 'default';


    const tracker = await this.getTracker(req);
    const key = this.generateKey(context, tracker, throttleName);

    const totalHits = await this.storageService.increment(key, ttl, limit, 1, throttleName);

    if(Number(totalHits) > limit) {
      res.setHeader('Retry-After', Math.ceil(ttl / 1000));
      throw new ThrottlerException('Too many requests');
    }

    res.setHeader(`${this.headerPrefix}-Limit`, limit);
    res.setHeader(`${this.headerPrefix}-Remaining`, Math.max(0, limit - Number(totalHits)));
    res.setHeader(`${this.headerPrefix}-Reset`, Date.now() + ttl);


    return true;
  }
}