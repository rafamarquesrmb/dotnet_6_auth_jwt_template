[![author](https://img.shields.io/badge/author-rafamarquesrmb-red.svg)](https://github.com/rafamarquesrmb) [![DotNET6](https://img.shields.io/badge/dotnet-6-blue.svg)](https://dotnet.microsoft.com/) [![C#10](https://img.shields.io/badge/csharp-10-blue.svg)](https://docs.microsoft.com/pt-br/dotnet/csharp/) [![License-Unlicense](https://img.shields.io/badge/License-Unlicense-green.svg)](https://unlicense.org)
# Tutorial sobre Autenticação e Autorização com JWT em WebAPI no Dotnet 6

Abaixo você pode ler todos os passos que levaram a conclusão do webapp deste repositório, criado em DOTNET 6, como WebApi.

<sub>Desenvolvido por [Rafael Marques](https://github.com/rafamarquesrmb)</sub>


# Autenticação e Autorização

A autenticação diz quem você é, e a autorização diz o que você pode fazer.

No caso de APIs, o usuário não fica “LOGADO” /autenticado na sua aplicação. A gente se autentica a cada requisição. Portanto inicialmente realizamos a autenticação, onde uma requisição enviando as credenciais do usuário são enviadas, e, se validas, retorna-se um token para esse usuário. A partir desse momento, quaisquer requisições que esse usuário queira fazer, ele deve enviar esse token junto a requisição (geralmente pelo headers) para poder comprovar sua autenticação.

Um dos padrões de Tokens mais utilizados é o JWT, ou seja, Json Web Token.

Dessa forma, a API "pega" esse token, o decifra e, assim, sabe qual é o usuário e qual o perfil de acesso desse usuário, tudo baseado nesse token. Ou seja, numa API, você se autentica a cada requisição.

O token é encriptado com uma chave que só nossa API vai possuir, dessa forma, é praticamente impossível alguém conseguir editar o token.

# Autenticação com Dotnet

O primeiro passo é criar nossa configuração, pode ser uma classe. Nesta configuração, vamos colocar a nossa chave que será utilizada para gerar o Token JWT.

```csharp
namespace AuthJwtDotnet
{
    public class Configuration
    {
        public static string JwtKey { get; set; } = "minhachavesecreta";
    }
}

```

No lugar de “minhachavesecreta” colocamos a chave que desejamos utilizar para encriptar o nosso token.

Devemos instalar dois packages na solução:

-   Microsoft.AspNetCore.Authentication
-   Microsoft.AspNetCore.Authentication.JwtBearer

`dotnet add package Microsoft.AspNetCore.Authentication`

`dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer`

Vale ressaltar que devemos ter uma classe Model para nosso user, no caso do nosso exemplo:

```csharp
namespace AuthJwtDotnet.Model
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }
}

```

## TokenService

Criamos então um **serviço** para nossos tokens, como **TokenService**.

```csharp
using AuthJwtDotnet.Model;
using System.IdentityModel.Tokens.Jwt;

namespace AuthJwtDotnet.Services
{
    public class TokenService
    {
        ...
    }
}

```

Vamos então criar o método GenerateToken, que será reponsável por gerar o token JWT para nosso usuário. Este método deve receber então o nosso User.

Dentro do nosso método generate, vamos iniciar com um JwtSecurityTokenHandler, no caso, instaciaremos esse handler dentro de token handller.

Instanciamos também a nossa key, porém devemos utilizar um array de Bytes para usa-la dentro do nosso handler, por isso, usamos o método Encoding.ASCII.GetBytes() do System.Text.

Instanciamos então um SecurityTokenDescriptor() para ser o nosso tokenDescriptor. A principio basta instaciarmos ela, em seguida voltamos para configura-la.

Criamos ainda a nossa variável token, que receberá esse token. Utilizamos o método CreateToken do TokenHandler, e passamos para ele o nosso tokenDescriptor.

Como nosso método GenerateToken deve retornar uma string, então utilizamos o método WriteToken do tokenHandler com o token para poder gerar a string e retorna-la.

Até esse momento, nosso código é algo como:

```csharp
using AuthJwtDotnet.Model;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthJwtDotnet.Services
{
    public class TokenService
    {
        public string GenerateToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(Configuration.JwtKey);

            var tokenDescriptor = new SecurityTokenDescriptor();

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}

```

Vamos então configurar o nosso TokenDescriptor. O TokenDescriptor pede alguns valores.

-   Expires = definimos o tempo de expiração do nosso Token
-   SigningCredentials = Como este token será gerado e será lido posteriormente. O signingCredentials vai esperar dois itens.
    -   O primeiro item é a nossa key. No nosso exemplos, vamos utilizar uma chave simétrica contendo a nossa key. Ex: new SymmetricSecurityKey(key)
    -   O segundo item é o algoritmo que será utilizado para encriptar esses itens. Existem vários algoritmos. Um que é bem interessante e seguro é o Hmac Sha256. Ex: SecurityAlgorithms.HmacSha256Signature

Portanto, neste momento, o nosso serviço ficará como:

```csharp
public class TokenService
    {
        public string GenerateToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(Configuration.JwtKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Expires = DateTime.UtcNow.AddHours(8),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }

```

## Injeção de dependência do TokenService para nossos controllers

Uma forma de utilizarmos nosso TokenService no dotnet é através da injeção de Dependencia. Digamos que temos uma classe chamada AccountController na nossa API.

Podemos realizar a injeção de dependencia de duas formas básicas:

```csharp
using AuthJwtDotnet.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthJwtDotnet.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly TokenService _tokenService;
    public AccountController(TokenService tokenService)
    {
        _tokenService = tokenService;
    }
}

```

Dessa forma podemos chamar o nosso _tokenService dentro de nossos métodos...

Ou podemos utilizar a injeção de dependencia através do próprio program.cs. Dessa forma podemos utilizar a Data Anotation [FromServices] nos nosso métodos. Ou seja:

```csharp
using AuthJwtDotnet.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthJwtDotnet.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    
    [HttpPost("/login")]
    public IActionResult Login([FromServices]TokenService _tokenService)
    {
        ...
    }
}

```

Porém, dessa forma, devemos indicar no nosso program.cs a dependencia do token service.

No nosso exemplo, vamos adciona-lo com o DesignPattern Transient. Poranto basta colocar o seguinte código:

```csharp
builder.Services.AddTransient<TokenService>();

```

Geralmente, colocamos abaixo de nosso AddControllers e DbContext...

## JWT Claims

Dentro do nosso TokenDescriptor, podemos configurar também um subject onde podemos passar um Claim para o nosso Token.

Podemos criar algo como:

```csharp
Subject = new ClaimsIdentity(new Claim[]
  {
      new Claim(ClaimTypes.Name,"Meu Nome"),
      new Claim(ClaimTypes.Role,"admin"),
      new Claim(ClaimTypes.Role,"user"),
  }),

```

Ao fazermos isso, estamos dizendo que o token gerado possuirá o nome “Meu Nome” e as Roles “admin” e “user”. O código do nosso token service será algo como:

```csharp
using AuthJwtDotnet.Model;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthJwtDotnet.Services
{
    public class TokenService
    {
        public string GenerateToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(Configuration.JwtKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name,"Rafael"),
                    new Claim(ClaimTypes.Role,"admin"),
                    new Claim(ClaimTypes.Role,"user"),
                }),
                Expires = DateTime.UtcNow.AddHours(8),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}

```

Porém, dessa forma, todos os tokens gerados possuirão essas mesmas características.

Para poder tornarmos dinâmico, podemos criar então uma extension para definir nossas claims baseadas em roles.

Por exemplo: criamos uma classe RoleClaimsExtension

```csharp
using AuthJwtDotnet.Model;
using System.Security.Claims;

namespace AuthJwtDotnet.Extensions
{
    public static class RoleClaimsExtension
    {
        public static IEnumerable<Claim> GetClaims(this User user)
        {
            var result = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };
            result.AddRange(
                user.Role.Select(role => new Claim(ClaimTypes.Role, user.Role))
                );
            return result;
        }
    }
}

```

Dessa forma, no nosso token service modificamos para chamar o getclaims do nosso usuário e passamos esse como parametro do subject. Então, nossa classe ficaria algo como:

```csharp
using AuthJwtDotnet.Extensions;
using AuthJwtDotnet.Model;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthJwtDotnet.Services
{
    public class TokenService
    {
        public string GenerateToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(Configuration.JwtKey);

            var claims = user.GetClaims();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(8),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}

```

## Indicando à aplicação que utilizamos Autenticação e Autorização

Devemos acrescentar ao nosso program.cs informando que a aplicação utilizar autenticação e autorização. Portanto, acima do nosso mapControllers e Run, acrescentamos:

```csharp
app.UseAuthentication();
app.UseAuthorization();

```


Também devemos acrescentar o nosso serviço de autenticação, onde definiremos o esquema de autorização a ser usado e o desafio desse esquema, e em seguida definimos que deve utilizar o JWT Bearer, onde enviamos nossos parâmetros de validação. Dessa forma, ficará algo assim, logo após no nosso builder:

```csharp
var key = Encoding.ASCII.GetBytes(Configuration.JwtKey);
builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(x =>
{
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

```

## Fim

Esse tutorial foi criado pensando em auxiliar a comunidade para ter um template simples de autênticação e autorização utilizando JWT em WebAPIs no Dotnet.
