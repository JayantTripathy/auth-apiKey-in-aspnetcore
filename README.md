# auth-apiKey-in-aspnetcore
Using API Key Authentication To Secure ASP.NET Core Web API
You can get all the details in the below blog link.
https://jayanttripathy.com/using-api-key-authentication-to-secure-asp-net-core-web-api/

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace APIKeyAuth.Middleware
{
    // You may need to install the Microsoft.AspNetCore.Http.Abstractions package into your project
    public class APIKeyMiddleware
    {
        private readonly RequestDelegate _next;
        const string APIKEY = "x-authKey";
        public APIKeyMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            if (!httpContext.Request.Headers.TryGetValue(APIKEY, out
                var extractedApiKey))
            {
                httpContext.Response.StatusCode = 401;
                await httpContext.Response.WriteAsync("Api Key missing ");
                return;
            }
            var appSettings = httpContext.RequestServices.GetRequiredService<IConfiguration>();
            var apiKey = appSettings.GetValue<string>(APIKEY);
            if (!apiKey.Equals(extractedApiKey))
            {
                httpContext.Response.StatusCode = 401;
                await httpContext.Response.WriteAsync("Wrong Auth Key : Unauthorized access");
                return;
            }
            await _next(httpContext);
        }
    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class APIKeyMiddlewareExtensions
    {
        public static IApplicationBuilder UseAPIKeyMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<APIKeyMiddleware>();
        }
    }
<img src="https://jayanttripathy.com/wp-content/uploads/2022/02/apikeyauth-200-Ok.png">

