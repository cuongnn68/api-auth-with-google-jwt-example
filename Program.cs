using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c => // only add swagger for ez test
        {
            c.SwaggerDoc("v1", new OpenApiInfo { Title = "You api title", Version = "v1" });
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Description = @"JWT Authorization header using the Bearer scheme. \r\n\r\n 
                      Enter 'Bearer' [space] and then your token in the text input below.
                      \r\n\r\nExample: 'Bearer 12345abcdef'",
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.ApiKey,
                Scheme = "Bearer"
            });

            c.AddSecurityRequirement(new OpenApiSecurityRequirement(){{
            new OpenApiSecurityScheme{
                Reference = new OpenApiReference{
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
                Scheme = "oauth2",
                Name = "Bearer",
                In = ParameterLocation.Header,

                },
            new List<string>()
          }
        });
        });

string? clientId = null; // put your client id if you want validate it
var googleTokenValidator = new GoogleTokenValidator(clientId);
builder.Services.AddAuthentication(options =>
        {
            // Bearer google_token
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.SecurityTokenValidators.Clear();
            options.SecurityTokenValidators.Add(googleTokenValidator);
        });
builder.Services
    .AddAuthorizationBuilder()
    .AddPolicy("Verify", option => option.RequireClaim(JwtRegisteredClaimNames.Email).RequireClaim("EmailVerified", true.ToString()))
    .AddPolicy("NotExistPolicy", option => option.RequireClaim("NotExistClaim"));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapGet("/not-need-auth", () => "hello");
app.MapGet("/need-authen", () => "authenticated").RequireAuthorization();
app.MapGet("/need-authorize", () => "authorized").RequireAuthorization("Verify");
app.MapGet("/need-authorize-but-dont-have", () => "should fail").RequireAuthorization("NotExistPolicy");

app.Run();


// https://stackoverflow.com/questions/48727900/google-jwt-authentication-with-aspnet-core-2-0
public class GoogleTokenValidator : ISecurityTokenValidator
{
    private readonly string? _clientId;
    private readonly JwtSecurityTokenHandler _tokenHandler;

    public GoogleTokenValidator(string? clientId)
    {
        _clientId = clientId;
        _tokenHandler = new JwtSecurityTokenHandler();
    }

    public bool CanValidateToken => true;

    public int MaximumTokenSizeInBytes { get; set; } = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;

    public bool CanReadToken(string securityToken)
    {
        return _tokenHandler.CanReadToken(securityToken);
    }

    public ClaimsPrincipal ValidateToken(string? securityToken, TokenValidationParameters? validationParameters, out SecurityToken? validatedToken)
    {
        try
        {
            Console.WriteLine(_clientId);
            validatedToken = null;
            var googleValidationSettings = string.IsNullOrWhiteSpace(_clientId)
                ? new GoogleJsonWebSignature.ValidationSettings()
                : new GoogleJsonWebSignature.ValidationSettings { Audience = new[] { _clientId } };
            var payload = GoogleJsonWebSignature.ValidateAsync(securityToken, googleValidationSettings).Result
                ?? throw new ArgumentNullException();
            validatedToken = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(securityToken);
            var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.NameId, payload.Name),
                    new Claim(JwtRegisteredClaimNames.Name, payload.Name),
                    new Claim(JwtRegisteredClaimNames.GivenName, payload.GivenName),
                    new Claim(JwtRegisteredClaimNames.Email, payload.Email),
                    new Claim("EmailVerified", payload.EmailVerified.ToString(), ClaimValueTypes.Boolean),
                    new Claim(JwtRegisteredClaimNames.Sub, payload.Subject),
                    new Claim(JwtRegisteredClaimNames.Iss, payload.Issuer),
                };
            var principle = new ClaimsPrincipal();
            principle.AddIdentity(new ClaimsIdentity(claims, JwtBearerDefaults.AuthenticationScheme));
            return principle;
        }
        catch (Exception e)
        {
            Debug.WriteLine(e);
            throw;
        }

    }
}