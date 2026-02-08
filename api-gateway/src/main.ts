import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(helmet({
    contentSecurityPolicy: {
      directives : {
        defaultSrc : ["'self'"],
        scriptSrc : ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        styleSrc : ["'self'", "'unsafe-inline'"],
        imgSrc : ["'self'", 'data:', 'https:'],
      }
    }
  }));

  app.enableCors({
    origin: (origin, callback) => {
      if(!origin) return callback(null, true);

      const allowedOrigins = process.env.CORS_ORIGIN?.split(',') || ['*'];

      if(allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },

    methods : ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type', 
      'Authorization',
      'X-Requested-With',
      'Accept',
      'Origin',
      'Access-Control-Allow-Origin',
      'Access-Control-Allow-Headers',
    ],
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    })
  );

  const config = new DocumentBuilder()
  .setTitle('Marketplace API Gateway')
  .setDescription('API Gateway for the Marketplace')
  .setVersion('1.0')
  .addBearerAuth()
  .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  const port = process.env.PORT || 3005;

  await app.listen(port);
  console.log(`API Gateway is running on port http://localhost:${port}`);
  console.log(`Swagger is running on port http://localhost:${port}/api`);
}
bootstrap();
