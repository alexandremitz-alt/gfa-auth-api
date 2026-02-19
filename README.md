# GFA Unified Admin - API Backend

API de autenticação centralizada para os sistemas GFA.

## Deploy no Railway

1. Fork este repositório
2. Conecte ao Railway
3. Configure as variáveis de ambiente:

```
MYSQL_HOST=seu_host
MYSQL_USER=seu_usuario
MYSQL_PASSWORD=sua_senha
MYSQL_DATABASE=seu_banco
JWT_SECRET=sua_chave_secreta
CORS_ORIGINS=https://seudominio.com
```

## Endpoints

- `POST /api/auth/login` - Login
- `POST /api/auth/validate?sistema=tag` - Validar usuário para sistema externo
- `GET /api/users` - Listar usuários
- `POST /api/users` - Criar usuário
- `GET /api/systems` - Listar sistemas
- `POST /api/systems` - Criar sistema
