# 📚 Resumo Completo da Aplicação - API Gateway Marketplace

## 🎯 O que é esta aplicação?

Esta é uma **API Gateway** construída com **NestJS** que funciona como um ponto de entrada único para um sistema de marketplace. Ela atua como um "porta-voz" que recebe todas as requisições dos clientes e as distribui para os serviços internos apropriados.

---

## 🏗️ Arquitetura da Aplicação

### Estrutura de Pastas

```
src/
├── main.ts                    # Ponto de entrada da aplicação
├── app.module.ts             # Módulo principal que organiza tudo
├── app.controller.ts          # Controlador principal
├── app.service.ts             # Serviço principal
│
├── auth/                      # Módulo de autenticação
│   ├── auth.module.ts         # Módulo de autenticação
│   ├── controllers/
│   │   └── auth.controller.ts # Controller de autenticação
│   ├── service/
│   │   └── auth.service.ts    # Serviço de autenticação (JWT)
│   ├── strategies/
│   │   └── jwt.strategy.ts    # Estratégia JWT do Passport
│   ├── decorators/
│   │   ├── public.decorator.ts    # Decorator @Public()
│   │   ├── roles.decorator.ts     # Decorator @Roles()
│   │   └── current-user.decorator.ts  # Decorator @CurrentUser()
│   └── interfaces/
│       └── user-session.interface.ts  # Interface de sessão
│
├── proxy/                     # Módulo de proxy
│   ├── proxy.module.ts
│   └── service/
│       └── proxy.service.ts   # Serviço que faz proxy para outros serviços
│
├── middleware/                # Middlewares
│   ├── middleware.module.ts
│   └── logging/
│       └── logging.middleware.ts  # Middleware de logging
│
├── guards/                    # Guards globais (proteções)
│   ├── throttler.guard.ts     # Guard de rate limiting
│   ├── auth.guard.ts          # Guard de autenticação JWT
│   ├── session.guard.ts       # Guard de validação de sessão
│   └── role.guard.ts          # Guard de autorização por roles
│
└── config/
    └── gateway.config.ts      # Configuração dos serviços backend
```

---

## 🔧 Componentes Principais Explicados

### 1. **Helmet** 🛡️

**O que é?**
Helmet é um middleware de segurança que ajuda a proteger sua aplicação Express/NestJS configurando vários cabeçalhos HTTP de segurança.

**Para que serve?**
- **Content Security Policy (CSP)**: Controla quais recursos (scripts, estilos, imagens) podem ser carregados
- **HSTS (HTTP Strict Transport Security)**: Força conexões HTTPS por 1 ano
- **Cross-Origin Embedder Policy**: Controla como recursos podem ser incorporados de outros domínios

**Exemplo na aplicação:**
```typescript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],           // Só permite recursos do próprio domínio
      scriptSrc: ["'self'", "'unsafe-inline'"],  // Permite scripts inline (necessário para Swagger)
      styleSrc: ["'self'", "'unsafe-inline'"],   // Permite estilos inline
      imgSrc: ["'self'", 'data:', 'https:'],     // Permite imagens de qualquer HTTPS
    }
  },
  hsts: {
    maxAge: 31536000,        // 1 ano em segundos
    includeSubDomains: true, // Aplica a todos os subdomínios
    preload: true,           // Permite pré-carregamento no navegador
  }
}));
```

**Analogia:** É como colocar um cofre e várias camadas de segurança na sua casa (API) para proteger contra invasores.

---

### 2. **CORS (Cross-Origin Resource Sharing)** 🌐

**O que é?**
CORS é um mecanismo de segurança do navegador que controla quais domínios podem fazer requisições para sua API.

**Para que serve?**
- Permite que aplicações frontend em outros domínios acessem sua API
- Bloqueia requisições de origens não autorizadas
- Controla quais métodos HTTP e cabeçalhos são permitidos

**Exemplo na aplicação:**
```typescript
app.enableCors({
  origin: (origin, callback) => {
    // Se não tem origem (ex: requisição do Postman), permite
    if(!origin) return callback(null, true);
    
    // Pega origens permitidas do .env ou permite todas
    const allowedOrigins = process.env.CORS_ORIGIN?.split(',') || ['*'];
    
    // Se permite todas ou a origem está na lista, autoriza
    if(allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      callback(null, true);  // ✅ Permite
    } else {
      callback(new Error('Not allowed by CORS'));  // ❌ Bloqueia
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', ...],
  credentials: true,  // Permite envio de cookies/credenciais
});
```

**Analogia:** É como um porteiro que verifica se você tem permissão para entrar no prédio (API) e de onde você está vindo.

---

### 3. **ValidationPipe** ✅

**O que é?**
Um pipe global do NestJS que valida automaticamente os dados de entrada das requisições.

**Para que serve?**
- **transform**: Converte automaticamente tipos (ex: string "123" → number 123)
- **whitelist**: Remove propriedades que não estão definidas no DTO
- **forbidNonWhitelisted**: Rejeita requisições com propriedades extras não permitidas

**Exemplo na aplicação:**
```typescript
app.useGlobalPipes(
  new ValidationPipe({
    transform: true,              // Converte tipos automaticamente
    whitelist: true,              // Remove propriedades não definidas
    forbidNonWhitelisted: true,   // Rejeita se tiver propriedades extras
  })
);
```

**Analogia:** É como um filtro que só deixa passar dados válidos e no formato correto, bloqueando dados maliciosos ou incorretos.

---

### 4. **ThrottlerGuard (Rate Limiting)** ⏱️

**O que é?**
Um guard global que limita a quantidade de requisições que um cliente pode fazer em um período de tempo.

**Para que serve?**
- **Proteção contra DDoS**: Previne ataques de negação de serviço
- **Previne abuso**: Evita que um usuário sobrecarregue o servidor
- **Economiza recursos**: Protege os serviços backend de sobrecarga
- **Headers informativos**: Adiciona headers HTTP com informações de limite e remanescente

**Configuração na aplicação:**
```typescript
ThrottlerModule.forRootAsync({
  imports: [ConfigModule],
  useFactory: (configService: ConfigService) => [
    {
      name: 'short',
      ttl: 1000,  // 1 segundo
      limit: configService.get<number>('RATE_LIMIT_SHORT', 10),
    },
    {
      name: 'medium',
      ttl: 60000,  // 1 minuto
      limit: configService.get<number>('RATE_LIMIT_MEDIUM', 100),
    },
    {
      name: 'long',
      ttl: 900000,  // 15 minutos
      limit: configService.get<number>('RATE_LIMIT_LONG', 1000),
    }
  ],
  inject: [ConfigService]
})
```

**CustomThrottlerGuard - Implementação Completa:**
```typescript
export class CustomThrottlerGuard extends ThrottlerGuard {
  // Rastreia requisições por IP + User-Agent
  protected getTracker(req: Record<string, any>): Promise<string> {
    return Promise.resolve(`${req.ip}-${req.headers['user-agent']}`);
  }

  // Implementação customizada com headers informativos
  protected async handleRequest(requestProps: ThrottlerRequest): Promise<boolean> {
    const { context, ttl, limit } = requestProps;
    const { req, res } = await this.getRequestResponse(context);
    
    const tracker = await this.getTracker(req);
    const key = this.generateKey(context, tracker, 'default');
    
    const totalHits = await this.storageService.increment(key, ttl, limit, 1, 'default');
    
    // Se excedeu o limite, retorna erro 429
    if (Number(totalHits) > limit) {
      res.setHeader('Retry-After', Math.ceil(ttl / 1000));
      throw new ThrottlerException('Too many requests');
    }
    
    // Adiciona headers informativos
    res.setHeader('X-RateLimit-Limit', limit);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, limit - Number(totalHits)));
    res.setHeader('X-RateLimit-Reset', Date.now() + ttl);
    
    return true;
  }
}
```

**Registro Global:**
```typescript
// app.module.ts
providers: [
  {
    provide: APP_GUARD,
    useClass: CustomThrottlerGuard  // Aplicado globalmente a todas as rotas
  }
]
```

**Headers retornados:**
- `X-RateLimit-Limit`: Limite máximo de requisições
- `X-RateLimit-Remaining`: Requisições restantes no período
- `X-RateLimit-Reset`: Timestamp de quando o limite será resetado
- `Retry-After`: Segundos para tentar novamente (quando excedido)

**Analogia:** É como um limitador de velocidade em uma estrada - você pode passar, mas não pode abusar. Se tentar fazer muitas requisições muito rápido, você é bloqueado temporariamente e recebe informações sobre quando pode tentar novamente.

---

### 5. **LoggingMiddleware** 📝

**O que é?**
Um middleware que registra todas as requisições HTTP que chegam na aplicação.

**Para que serve?**
- **Monitoramento**: Acompanha todas as requisições
- **Debugging**: Ajuda a encontrar problemas
- **Auditoria**: Registra quem acessou o quê e quando
- **Performance**: Mede o tempo de resposta

**O que ele registra:**
```typescript
// Quando a requisição chega:
- Método HTTP (GET, POST, etc.)
- URL acessada
- IP do cliente
- User-Agent (navegador/aplicação)

// Quando a resposta é enviada:
- Status code (200, 404, 500, etc.)
- Tamanho da resposta
- Tempo de processamento (duração)
- Erros (se houver)
```

**Analogia:** É como um sistema de câmeras de segurança que registra todas as entradas e saídas, com informações detalhadas sobre cada visita.

---

### 6. **ProxyService** 🔄

**O que é?**
Um serviço que recebe requisições e as repassa para os serviços backend apropriados.

**Para que serve?**
- **Roteamento**: Direciona requisições para o serviço correto
- **Abstração**: Cliente não precisa saber onde cada serviço está
- **Enriquecimento**: Adiciona informações do usuário nos headers
- **Health Check**: Verifica se os serviços estão funcionando

**Serviços configurados:**
```typescript
// gateway.config.ts
{
  users: 'http://localhost:3000',      // Serviço de usuários
  products: 'http://localhost:3001',   // Serviço de produtos
  checkout: 'http://localhost:3002',   // Serviço de checkout
  payments: 'http://localhost:3003',   // Serviço de pagamentos
}
```

**Funcionalidades:**
1. **proxyRequest()**: Faz proxy de requisições para serviços backend
   - Adiciona headers com informações do usuário (ID, email, role)
   - Gerencia timeouts
   - Trata erros

2. **getServiceHealth()**: Verifica se um serviço está saudável
   - Faz requisição para `/health` de cada serviço
   - Retorna status (healthy/unhealthy)

**Analogia:** É como um recepcionista de hotel que recebe seus pedidos e os encaminha para o departamento correto (cozinha, limpeza, etc.), adicionando informações relevantes no processo.

---

### 7. **AuthModule (Módulo de Autenticação)** 🔐

**O que é?**
Módulo completo responsável por toda a autenticação e autorização da aplicação.

**Componentes do módulo:**

#### **7.1 AuthService** 🔑

**O que é?**
Serviço que gerencia todas as operações de autenticação.

**Métodos implementados:**

1. **validateJwtToken(token: string)**
   - Valida tokens JWT usando o `JwtService`
   - Retorna os dados do token se válido
   - Lança `UnauthorizedException` se inválido

2. **validateSessionToken(sessionToken: string)**
   - Valida tokens de sessão fazendo requisição ao serviço de usuários
   - Retorna dados da sessão do usuário
   - Lança `UnauthorizedException` se inválido

3. **login(loginDto: { email, password })**
   - Autentica usuário fazendo requisição ao serviço de usuários
   - Retorna dados do usuário e token de autenticação
   - Lança `UnauthorizedException` se credenciais inválidas

4. **register(registerDto: { email, password })**
   - Registra novo usuário no serviço de usuários
   - Retorna dados do usuário criado
   - Lança `UnauthorizedException` se falhar

**Tecnologias usadas:**
- **JWT (JSON Web Tokens)**: Tokens de autenticação
- **Passport**: Framework de autenticação
- **@nestjs/jwt**: Módulo JWT do NestJS
- **@nestjs/axios**: Para comunicação com serviço de usuários

**Configuração:**
```typescript
JwtModule.registerAsync({
  imports: [ConfigModule],
  useFactory: async (configService: ConfigService) => ({
    secret: configService.get<string>('JWT_SECRET'),
    signOptions: {
      expiresIn: '24h'  // Tokens expiram em 24 horas
    }
  }),
  inject: [ConfigService]
})
```

#### **7.2 AuthController** 🎮

**O que é?**
Controller que expõe os endpoints de autenticação.

**Endpoints:**

- **POST `/auth/login`**
  - Autentica um usuário
  - Recebe: `{ email, password }`
  - Retorna: Dados do usuário e token JWT
  - Status: 200 (OK) ou 401 (Unauthorized)

- **POST `/auth/register`**
  - Registra um novo usuário
  - Recebe: Dados de registro
  - Retorna: Dados do usuário criado
  - Status: 201 (Created) ou 400 (Bad Request)

**Documentação Swagger:**
- Tag: "Authentication"
- Documentado com `@ApiOperation` e `@ApiResponse`

#### **7.3 JwtStrategy** 🎫

**O que é?**
Estratégia do Passport para autenticação via JWT.

**Como funciona:**
1. Extrai o token JWT do header `Authorization: Bearer <token>`
2. Valida o token usando a chave secreta
3. Chama o método `validate()` com o payload do token
4. O método `validate()` verifica o token via `AuthService`
5. Retorna dados do usuário (userId, email, role)

**Configuração:**
```typescript
super({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  ignoreExpiration: false,
  secretOrKey: process.env.JWT_SECRET,
})
```

#### **7.4 JwtAuthGuard** 🛡️

**O que é?**
Guard que protege rotas exigindo autenticação JWT.

**Funcionalidades:**
- **Proteção de rotas**: Bloqueia acesso não autenticado
- **Rotas públicas**: Permite marcar rotas como públicas usando decorator `@Public()`
- **Validação de usuário**: Verifica se o usuário está autenticado
- **Integração com Passport**: Usa a estratégia JWT do Passport

**Como usar:**
```typescript
// Proteger uma rota
@UseGuards(JwtAuthGuard)
@Get('protected')
getProtectedData() { ... }

// Tornar uma rota pública
@Public()
@Get('public')
getPublicData() { ... }
```

**Implementação:**
```typescript
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private readonly reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      context.getHandler(),
      context.getClass()
    ]);
    
    if (isPublic) return true;  // Permite acesso sem autenticação
    
    return super.canActivate(context);  // Exige autenticação JWT
  }

  handleRequest(err: any, user: any, info: any): any {
    if (err || !user) {
      throw err || new UnauthorizedException();
    }
    return user;
  }
}
```

#### **7.5 SessionGuard** 🔐

**O que é?**
Guard que valida tokens de sessão via header `x-session-token`.

**Para que serve?**
- **Autenticação alternativa**: Permite autenticação via tokens de sessão
- **Validação de sessão**: Verifica se a sessão é válida no serviço de usuários
- **Enriquecimento de request**: Adiciona dados do usuário ao objeto request

**Como funciona:**
1. Extrai o token do header `x-session-token`
2. Valida o token fazendo requisição ao serviço de usuários
3. Verifica se a sessão é válida e se tem usuário associado
4. Adiciona `request.user` com os dados do usuário

**Como usar:**
```typescript
@UseGuards(SessionGuard)
@Get('protected')
getProtectedData(@CurrentUser() user) {
  // user contém os dados do usuário da sessão
  return { message: `Hello ${user.email}` };
}
```

**Implementação:**
```typescript
export class SessionGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const sessionToken = request.headers['x-session-token'];

    if (!sessionToken) {
      throw new UnauthorizedException('Session token is required');
    }

    const session = await this.authService.validateSessionToken(sessionToken);
    
    if (!session.valid || !session.user) {
      throw new UnauthorizedException('Invalid session token');
    }

    request.user = session.user;
    return true;
  }
}
```

#### **7.6 RoleGuard** 👮

**O que é?**
Guard que verifica se o usuário tem as roles necessárias para acessar uma rota.

**Para que serve?**
- **Autorização baseada em roles**: Controla acesso baseado em permissões
- **Proteção de recursos**: Bloqueia acesso de usuários sem permissão adequada
- **Mensagens descritivas**: Informa quais roles são necessárias quando bloqueado

**Como usar:**
```typescript
@UseGuards(JwtAuthGuard, RoleGuard)
@Roles('admin', 'moderator')
@Get('admin-only')
getAdminData() { ... }
```

**Implementação:**
```typescript
export class RoleGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>('roles', [
      context.getHandler(),
      context.getClass()
    ]);

    if (!requiredRoles) return true;  // Se não tem roles requeridas, permite

    const user = context.switchToHttp().getRequest().user;

    if (!user || !user.role) {
      throw new ForbiddenException('User role not authorized');
    }

    const hasRole = requiredRoles.includes(user.role);

    if (!hasRole) {
      throw new ForbiddenException(
        `User role ${user.role} is not authorized. Required: ${requiredRoles.join(', ')}`
      );
    }

    return true;
  }
}
```

#### **7.7 Decorators de Autenticação** 🏷️

**@Public()** - Marca rota como pública
```typescript
@Public()
@Get('public-endpoint')
getPublicData() { ... }
```

**@Roles(...roles)** - Define roles necessárias
```typescript
@Roles('admin', 'moderator')
@Get('admin-endpoint')
getAdminData() { ... }
```

**@CurrentUser()** - Injeta dados do usuário autenticado
```typescript
@Get('profile')
getProfile(@CurrentUser() user) {
  return user;  // Retorna dados do usuário do request
}
```

**Analogia:** É como um sistema completo de segurança de um prédio:
- **AuthService**: O sistema que verifica identidades
- **AuthController**: A recepção onde você se registra/entra
- **JwtStrategy**: O leitor de crachás
- **JwtAuthGuard**: O segurança que verifica se você tem permissão para entrar
- **SessionGuard**: Um segurança alternativo que aceita outro tipo de credencial
- **RoleGuard**: O segurança que verifica se você tem o nível de acesso necessário
- **Decorators**: As etiquetas que indicam quem pode acessar cada área

---

### 8. **Swagger** 📖

**O que é?**
Uma ferramenta que gera documentação interativa da API automaticamente.

**Para que serve?**
- **Documentação automática**: Cria documentação baseada no código
- **Teste interativo**: Permite testar a API diretamente do navegador
- **Descoberta de endpoints**: Facilita entender quais endpoints existem

**Acesso:**
- URL: `http://localhost:3005/api`
- Interface visual para explorar e testar a API

**Analogia:** É como um catálogo interativo de um restaurante onde você pode ver todos os pratos (endpoints) disponíveis e até fazer pedidos (testar requisições) diretamente.

---

## 🔒 Camadas de Segurança Implementadas

A aplicação implementa múltiplas camadas de segurança em defesa em profundidade:

### Camada 1: Headers de Segurança (Helmet)
- **Content Security Policy**: Previne XSS attacks
- **HSTS**: Força conexões HTTPS
- **Cross-Origin Embedder Policy**: Controla incorporação de recursos

### Camada 2: CORS
- **Controle de origem**: Apenas origens permitidas podem acessar
- **Métodos permitidos**: Controla quais métodos HTTP são aceitos
- **Headers permitidos**: Define quais headers podem ser enviados

### Camada 3: Rate Limiting (ThrottlerGuard)
- **Proteção DDoS**: Limita requisições por IP + User-Agent
- **Múltiplos níveis**: Short (1s), Medium (1min), Long (15min)
- **Configurável**: Via variáveis de ambiente
- **Headers informativos**: Cliente sabe quantas requisições restam

### Camada 4: Validação de Dados (ValidationPipe)
- **Sanitização**: Remove propriedades não permitidas
- **Transformação**: Converte tipos automaticamente
- **Rejeição**: Bloqueia dados maliciosos ou incorretos

### Camada 5: Autenticação (JwtAuthGuard / SessionGuard)
- **JWT**: Autenticação via tokens Bearer
- **Sessão**: Autenticação alternativa via tokens de sessão
- **Rotas públicas**: Sistema de bypass para rotas públicas (@Public())

### Camada 6: Autorização (RoleGuard)
- **Controle de acesso**: Baseado em roles/permissões
- **Mensagens descritivas**: Informa quais roles são necessárias
- **Flexível**: Pode ser combinado com outros guards

### Camada 7: Logging
- **Auditoria**: Registra todas as requisições
- **Monitoramento**: Detecta padrões suspeitos
- **Debugging**: Facilita investigação de problemas

**Resumo Visual:**
```
Requisição
    ↓
[Helmet] → Headers de segurança
    ↓
[CORS] → Verifica origem
    ↓
[ThrottlerGuard] → Rate limiting
    ↓
[ValidationPipe] → Valida dados
    ↓
[JwtAuthGuard] → Autenticação
    ↓
[RoleGuard] → Autorização
    ↓
[Controller] → Processa requisição
```

---

## 🔄 Fluxo de uma Requisição

### Fluxo Geral

```
1. Cliente faz requisição
   ↓
2. Helmet adiciona headers de segurança
   ↓
3. CORS verifica se a origem é permitida
   ↓
4. LoggingMiddleware registra a requisição
   ↓
5. CustomThrottlerGuard (APP_GUARD) verifica rate limiting globalmente
   ↓
6. ValidationPipe valida os dados
   ↓
7. JwtAuthGuard verifica autenticação (se rota protegida, ignora se @Public())
   ↓
8. RoleGuard verifica autorização por roles (se @Roles() presente)
   ↓
9. Controller recebe a requisição
   ↓
10. Service processa a requisição
   ↓
11. ProxyService encaminha para serviço backend (se necessário)
   ↓
12. Resposta volta pelo mesmo caminho
   ↓
13. LoggingMiddleware registra a resposta
   ↓
14. Cliente recebe a resposta com headers de rate limiting
```

### Fluxo de Autenticação (Login)

```
1. Cliente faz POST /auth/login com { email, password }
   ↓
2. ValidationPipe valida os dados
   ↓
3. AuthController recebe a requisição
   ↓
4. AuthService.login() é chamado
   ↓
5. AuthService faz requisição POST para Users Service /login
   ↓
6. Users Service valida credenciais e retorna dados do usuário
   ↓
7. AuthService retorna dados do usuário e token JWT
   ↓
8. Cliente recebe token JWT
```

### Fluxo de Requisição Protegida

```
1. Cliente faz requisição com header: Authorization: Bearer <token>
   ↓
2. JwtAuthGuard intercepta a requisição
   ↓
3. Verifica se a rota é pública (@Public())
   - Se pública: permite acesso
   - Se protegida: continua
   ↓
4. JwtStrategy extrai token do header
   ↓
5. JwtStrategy valida token usando JWT_SECRET
   ↓
6. JwtStrategy.validate() chama AuthService.validateJwtToken()
   ↓
7. Se token válido: adiciona dados do usuário ao request
   ↓
8. Se token inválido: lança UnauthorizedException
   ↓
9. Controller recebe requisição com dados do usuário
   ↓
10. Processa requisição normalmente
```

---

## 📦 Dependências Principais

### Segurança
- **helmet**: Headers de segurança HTTP
- **@nestjs/throttler**: Rate limiting
- **@nestjs/jwt**: Autenticação JWT
- **@nestjs/passport**: Framework de autenticação
- **passport-jwt**: Estratégia JWT para Passport

### Funcionalidades
- **@nestjs/axios**: Cliente HTTP para fazer requisições
- **@nestjs/swagger**: Documentação da API
- **@nestjs/config**: Gerenciamento de variáveis de ambiente
- **class-validator**: Validação de dados
- **class-transformer**: Transformação de dados

### Core
- **@nestjs/core**: Framework principal
- **@nestjs/common**: Utilitários comuns
- **rxjs**: Programação reativa

---

## 🚀 Como Executar

```bash
# Instalar dependências
pnpm install

# Desenvolvimento (com hot-reload)
pnpm start:dev

# Produção
pnpm build
pnpm start:prod
```

**Variáveis de ambiente necessárias:**
```env
PORT=3005
CORS_ORIGIN=http://localhost:3000,http://localhost:3001
JWT_SECRET=sua-chave-secreta-aqui

# Rate Limiting (opcional, valores padrão serão usados se não definidos)
RATE_LIMIT_SHORT=10
RATE_LIMIT_MEDIUM=100
RATE_LIMIT_LONG=1000

# Serviços Backend
USERS_SERVICE_URL=http://localhost:3000
PRODUCTS_SERVICE_URL=http://localhost:3001
CHECKOUT_SERVICE_URL=http://localhost:3002
PAYMENTS_SERVICE_URL=http://localhost:3003
```

---

## 🎓 Conceitos Importantes

### **API Gateway Pattern**
Um padrão arquitetural onde um único ponto de entrada (gateway) gerencia todas as requisições e as roteia para os serviços apropriados. Benefícios:
- **Centralização**: Toda lógica de roteamento em um lugar
- **Segurança**: Uma camada de segurança única
- **Simplicidade**: Cliente só precisa conhecer uma URL

### **Microserviços**
A aplicação se comunica com vários serviços independentes:
- Cada serviço tem sua responsabilidade específica
- Serviços podem ser desenvolvidos e deployados independentemente
- Gateway facilita a comunicação entre eles

### **Middleware**
Código que executa antes/depois das requisições:
- Executa em ordem sequencial
- Pode modificar requisições/respostas
- Pode bloquear requisições

### **Guards**
Proteções que decidem se uma requisição pode prosseguir:
- Executam antes dos controllers
- Podem bloquear requisições não autorizadas
- Exemplos: `JwtAuthGuard` (autenticação), `ThrottlerGuard` (rate limiting)

### **Strategies (Passport)**
Estratégias de autenticação do Passport:
- Define como extrair e validar credenciais
- `JwtStrategy`: Extrai token JWT do header e valida
- Pode ter múltiplas estratégias (JWT, Local, OAuth, etc.)

### **Decorators Personalizados**
Marcadores que adicionam metadados às rotas:
- `@Public()`: ✅ Marca rota como pública (não requer autenticação) - **Implementado**
- `@Roles(...roles)`: ✅ Define roles necessárias para acessar a rota - **Implementado**
- `@CurrentUser()`: ✅ Injeta dados do usuário autenticado no parâmetro - **Implementado**
- `@UseGuards()`: Aplica guards específicos a rotas
- `@ApiTags()`: Organiza endpoints no Swagger

**Implementação dos Decorators:**

**@Public():**
```typescript
// src/auth/decorators/public.decorator.ts
import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

**@Roles():**
```typescript
// src/auth/decorators/roles.decorator.ts
import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
```

**@CurrentUser():**
```typescript
// src/auth/decorators/current-user.decorator.ts
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  }
);
```

**Uso combinado:**
```typescript
@Public()  // Rota pública
@Get('public')
getPublicData() { ... }

@Roles('admin')  // Requer role admin
@UseGuards(JwtAuthGuard, RoleGuard)
@Get('admin')
getAdminData(@CurrentUser() user) {
  return { message: `Hello admin ${user.email}` };
}
```

---

## 🔍 Endpoints Disponíveis

### Endpoints Públicos

#### GET `/`
- Retorna mensagem de boas-vindas
- **Autenticação**: Não requerida

#### GET `/health`
- Verifica saúde da API Gateway
- Verifica saúde de todos os serviços backend
- Retorna status de cada serviço
- **Autenticação**: Não requerida

#### GET `/api`
- Documentação Swagger da API
- Interface interativa para testar endpoints
- **Autenticação**: Não requerida

### Endpoints de Autenticação

#### POST `/auth/login`
- Autentica um usuário
- **Body**: `{ email: string, password: string }`
- **Resposta**: Dados do usuário e token JWT
- **Status**: 200 (OK) ou 401 (Unauthorized)
- **Autenticação**: Não requerida (público)

#### POST `/auth/register`
- Registra um novo usuário
- **Body**: Dados de registro do usuário
- **Resposta**: Dados do usuário criado
- **Status**: 201 (Created) ou 400 (Bad Request)
- **Autenticação**: Não requerida (público)

### Endpoints Protegidos

Para acessar endpoints protegidos, inclua o token JWT no header:
```
Authorization: Bearer <seu-token-jwt>
```

**Exemplo de uso:**
```bash
curl -X GET http://localhost:3005/protected-route \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

---

## 💡 Dicas de Uso

1. **Desenvolvimento**: Use `pnpm start:dev` para hot-reload
2. **Testes**: Acesse `/api` para ver e testar todos os endpoints
3. **Logs**: Monitore o console para ver logs de requisições
4. **Rate Limiting**: Se receber erro 429, você excedeu o limite
5. **CORS**: Configure `CORS_ORIGIN` no `.env` para permitir seu frontend

---

## 🛠️ Próximos Passos Sugeridos

### ✅ Segurança - Concluído
1. ✅ ~~Implementar métodos do `AuthService`~~ (Concluído)
2. ✅ ~~Criar `AuthController` com endpoints de login/register~~ (Concluído)
3. ✅ ~~Implementar `JwtAuthGuard` para proteção de rotas~~ (Concluído)
4. ✅ ~~Criar `JwtStrategy` para autenticação JWT~~ (Concluído)
5. ✅ ~~Criar decorator `@Public()` para marcar rotas públicas~~ (Concluído)
6. ✅ ~~Implementar `SessionGuard` para validação de sessões~~ (Concluído)
7. ✅ ~~Implementar `RoleGuard` para autorização baseada em roles~~ (Concluído)
8. ✅ ~~Criar decorators `@Roles()` e `@CurrentUser()`~~ (Concluído)
9. ✅ ~~Configurar `ThrottlerGuard` globalmente com APP_GUARD~~ (Concluído)
10. ✅ ~~Implementar `CustomThrottlerGuard` com headers informativos~~ (Concluído)
11. ✅ ~~Configurar rate limiting via variáveis de ambiente~~ (Concluído)

### 🚀 Próximas Funcionalidades
1. Criar controllers específicos para cada serviço (products, checkout, etc.)
2. Implementar refresh tokens para renovação de tokens JWT
3. Adicionar validação de DTOs com `class-validator` nos endpoints
4. Implementar cache para melhorar performance
5. Adicionar métricas e monitoramento (Prometheus, Grafana)
6. Implementar circuit breaker para resiliência
7. Adicionar testes unitários e de integração
8. Implementar logging estruturado (Winston, Pino)
9. Adicionar health checks mais detalhados
10. Implementar graceful shutdown

---

## 📚 Recursos para Aprender Mais

- [NestJS Documentation](https://docs.nestjs.com/)
- [Helmet Documentation](https://helmetjs.github.io/)
- [CORS Explained](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [JWT Authentication](https://jwt.io/)
- [API Gateway Pattern](https://microservices.io/patterns/apigateway.html)

---

**Desenvolvido com ❤️ usando NestJS**

