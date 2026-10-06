using AuthenticationSdk.util;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationSdk.core
{
    /// <summary>
    /// Extension methods for registering CyberSource Authentication SDK services with a
    /// <see cref="IServiceCollection"/>.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the certificate/key cache (<see cref="ICache"/>) with the container.
        /// <para>
        /// The cache is registered as a singleton that resolves to the
        /// same shared instance used by the static <see cref="Cache"/> facade (<see cref="CertificateCache.Default"/>).
        /// Registering the existing instance (rather than the type) guarantees a single, process-wide cache is used
        /// whether callers resolve <see cref="ICache"/> via dependency injection or call the static facade directly.
        /// </para>
        /// </summary>
        /// <param name="services">The service collection to add the registration to.</param>
        /// <returns>The same <see cref="IServiceCollection"/> instance so that calls can be chained.</returns>
        public static IServiceCollection AddCertificateCache(this IServiceCollection services)
        {
            services.AddSingleton<ICache>(CertificateCache.Default);
            return services;
        }
    }
}
