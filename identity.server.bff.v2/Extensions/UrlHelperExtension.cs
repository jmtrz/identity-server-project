using Microsoft.AspNetCore.Http;
using System;

namespace identity.server.bff.v2.Extensions;

public static class UrlHelperExtension
{
    public static bool IsLocalUrl(this string url,HttpRequest request)
    {
        if (string.IsNullOrEmpty(url)) return false;

        if (url.StartsWith("/")) return !url.StartsWith("//") && !url.StartsWith("/\\");

        try
        {
            var uri = new Uri(url);
            return uri.Host.Equals(request.Host.Value, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }

    }
}
