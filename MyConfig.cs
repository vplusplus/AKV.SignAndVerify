
using Microsoft.Extensions.Configuration;

namespace AKV.SignAndVerify
{
    internal static class MyConfig
    {

        static readonly Lazy<IConfiguration> LazyConfiguration = new Lazy<IConfiguration>(BuildConfigurationOnce);

        static IConfiguration BuildConfigurationOnce()
        {
            return new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();
        }

        internal static string AppSetting(string name, string defaultValue)
        {
            var something = LazyConfiguration.Value.GetSection("appSettings")?[name];

            return string.IsNullOrWhiteSpace(something) 
                ? defaultValue 
                : something;
        }

        internal static string AppSetting(string name)
        {
            var something = LazyConfiguration.Value.GetSection("appSettings")?[name];

            return string.IsNullOrWhiteSpace(something)
                ? throw new Exception($"Missing appSetting '{name}'")
                : something;
        }
    }
}
