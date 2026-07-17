using System;
using System.Text;
using System.Text.Json;

namespace System.Text.Json.Nodes
{
    /// <summary>
    /// Polyfills JsonNode.GetValueKind() for target frameworks where the
    /// instance method is not available.
    ///
    /// On .NET 8+, JsonNode already has an instance GetValueKind() method.
    /// Instance methods take precedence over extension methods, so this
    /// extension will not interfere with the platform implementation.
    /// </summary>
    public static class JsonNodeGetValueKindPolyfill
    {
        /// <summary>
        /// Returns the JsonValueKind represented by the current JsonNode.
        /// </summary>
        /// <param name="node">The JSON node to inspect.</param>
        /// <returns>The corresponding JsonValueKind.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="node"/> is null.
        /// </exception>
        public static JsonValueKind GetValueKind(this JsonNode node)
        {
            if (node is null)
                throw new ArgumentNullException(nameof(node));

            if (node is JsonObject)
                return JsonValueKind.Object;

            if (node is JsonArray)
                return JsonValueKind.Array;

            if (node is JsonValue value)
                return GetJsonValueKind(value);

            return JsonValueKind.Undefined;
        }

        private static JsonValueKind GetJsonValueKind(JsonValue value)
        {
            /*
             * JsonValue can wrap:
             * - a JsonElement, often when parsed from JSON;
             * - CLR primitives, such as string, bool, int, double, etc.;
             * - other values supported by System.Text.Json.
             *
             * First, handle JsonElement because it already exposes ValueKind.
             */
            if (value.TryGetValue<JsonElement>(out JsonElement element))
                return element.ValueKind;

            /*
             * Then handle common primitive JsonValue cases without serializing.
             */
            if (value.TryGetValue<string>(out _))
                return JsonValueKind.String;

            if (value.TryGetValue<bool>(out bool boolean))
                return boolean ? JsonValueKind.True : JsonValueKind.False;

            if (IsNumber(value))
                return JsonValueKind.Number;

            /*
             * Fallback:
             * For less common JsonValue payloads, serialize the value and parse
             * just enough to determine the JSON token kind. This keeps behavior
             * aligned with the actual JSON representation.
             */
            using JsonDocument document = JsonDocument.Parse(value.ToJsonString());
            return document.RootElement.ValueKind;
        }

        private static bool IsNumber(JsonValue value)
        {
            return
                value.TryGetValue<byte>(out _) ||
                value.TryGetValue<sbyte>(out _) ||
                value.TryGetValue<short>(out _) ||
                value.TryGetValue<ushort>(out _) ||
                value.TryGetValue<int>(out _) ||
                value.TryGetValue<uint>(out _) ||
                value.TryGetValue<long>(out _) ||
                value.TryGetValue<ulong>(out _) ||
                value.TryGetValue<float>(out _) ||
                value.TryGetValue<double>(out _) ||
                value.TryGetValue<decimal>(out _);
        }
    }
}