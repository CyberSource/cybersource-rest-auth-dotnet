using System;
using System.Collections.Generic;
using NUnit.Framework;
using AuthenticationSdk.util;
using System.Text.Json.Nodes;
using System.Text.Json;

namespace AuthenticationSdkTests.NetCore.util
{
    [TestFixture]
    public class LogUtilityTests
    {
        private LogUtility logUtility;

        [SetUp]
        public void SetUp()
        {
            logUtility = new LogUtility();
        }

        // --- MaskSensitiveData(string) with JObject input ---

        [Test]
        public void MaskSensitiveData_JsonObject_MasksSensitiveStringFields()
        {
            string input = "{\"number\":\"4111111111111111\",\"merchantId\":\"testMerchant\"}";
            string result = logUtility.MaskSensitiveData(input);

            JsonNode? parsed = JsonNode.Parse(result);
            Assert.That(parsed, Is.Not.Null);

            JsonNode? parsedNode1 = parsed!["number"];
            Assert.That(parsedNode1, Is.Not.Null);
            Assert.That(parsedNode1.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));

            JsonNode? parsedNode2 = parsed!["merchantId"];
            Assert.That(parsedNode2, Is.Not.Null);
            Assert.That(parsedNode2.ToString(), Is.EqualTo("testMerchant"));
        }

        [Test]
        public void MaskSensitiveData_JsonObject_MasksSensitiveIntegerFields()
        {
            string input = "{\"securityCode\":123,\"amount\":500}";
            string result = logUtility.MaskSensitiveData(input);

            JsonNode? parsed = JsonNode.Parse(result);
            Assert.That(parsed, Is.Not.Null);

            JsonNode? parsedNode1 = parsed!["securityCode"];
            Assert.That(parsedNode1, Is.Not.Null);
            Assert.That(parsedNode1.ToString(), Is.EqualTo("XXXXX"));

            JsonNode? parsedNode2 = parsed!["amount"];
            Assert.That(parsedNode2, Is.Not.Null);
            Assert.That(parsedNode2.GetValue<int>(), Is.EqualTo(500));
        }

        [Test]
        public void MaskSensitiveData_JsonObject_MasksNestedSensitiveFields()
        {
            string input = "{\"payment\":{\"number\":\"4111111111111111\",\"securityCode\":\"123\"}}";
            string result = logUtility.MaskSensitiveData(input);

            JsonNode? parsed = JsonNode.Parse(result);
            Assert.That(parsed, Is.Not.Null);

            JsonNode? payment = parsed["payment"];

            JsonNode? parsedNode1 = payment!["number"];
            Assert.That(parsedNode1, Is.Not.Null);
            Assert.That(parsedNode1.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));

            JsonNode? parsedNode2 = payment!["securityCode"];
            Assert.That(parsedNode2, Is.Not.Null);
            Assert.That(parsedNode2.ToString(), Is.EqualTo("XXX"));
        }

        [Test]
        public void MaskSensitiveData_JsonObject_NonSensitiveFieldsUnchanged()
        {
            string input = "{\"merchantId\":\"test\",\"currency\":\"USD\"}";
            string result = logUtility.MaskSensitiveData(input);

            JsonNode? parsed = JsonNode.Parse(result);
            Assert.That(parsed, Is.Not.Null);

            JsonNode? parsedNode1 = parsed!["merchantId"];
            Assert.That(parsedNode1, Is.Not.Null);
            Assert.That(parsedNode1.ToString(), Is.EqualTo("test"));

            JsonNode? parsedNode2 = parsed!["currency"];
            Assert.That(parsedNode2, Is.Not.Null);
            Assert.That(parsedNode2.ToString(), Is.EqualTo("USD"));
        }

        // --- MaskSensitiveData(string) with JArray input ---

        [Test]
        public void MaskSensitiveData_JsonArray_MasksSensitiveFieldsInObjectElements()
        {
            string input = "[{\"number\":\"4111111111111111\"},{\"merchantId\":\"test\"}]";
            string result = logUtility.MaskSensitiveData(input);

            JsonNode? parsed = JsonNode.Parse(result);
            Assert.That(parsed, Is.Not.Null);

            JsonArray parsedArray = parsed!.AsArray();
            Assert.That(parsedArray, Is.Not.Null);

            JsonNode? parsedNode1 = parsedArray[0]!["number"];
            Assert.That(parsedNode1, Is.Not.Null);
            Assert.That(parsedNode1.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));

            JsonNode? parsedNode2 = parsedArray[1]!["merchantId"];
            Assert.That(parsedNode2, Is.Not.Null);
            Assert.That(parsedNode2.ToString(), Is.EqualTo("test"));
        }

        [Test]
        public void MaskSensitiveData_JsonArray_TopLevelArrayNotInSensitiveContext()
        {
            // Top-level arrays are parsed with isSensitiveContext=false,
            // so primitive values in the array should NOT be masked
            string input = "[\"plainValue\",123]";
            string result = logUtility.MaskSensitiveData(input);

            JsonNode? parsed = JsonNode.Parse(result);
            Assert.That(parsed, Is.Not.Null);

            JsonArray parsedArray = parsed!.AsArray();
            Assert.That(parsedArray, Is.Not.Null);

            JsonNode? parsedNode1 = parsedArray[0]!;
            Assert.That(parsedNode1, Is.Not.Null);
            Assert.That(parsedNode1.ToString(), Is.EqualTo("plainValue"));

            JsonNode? parsedNode2 = parsedArray[1]!;
            Assert.That(parsedNode2, Is.Not.Null);
            Assert.That(parsedNode2.GetValue<int>(), Is.EqualTo(123));
        }

        // --- MaskSensitiveData(string) with non-JSON input ---

        [Test]
        public void MaskSensitiveData_NonJsonString_AppliesRegexMasking()
        {
            // Non-JSON strings fall through to regex masking with authentication tags
            string input = "This is plain text with no JSON";
            string result = logUtility.MaskSensitiveData(input);

            // Should not throw, result should be a string (regex applied if matched)
            Assert.That(result, Is.Not.Null);
        }

        // --- MaskSensitiveDataInJsonContainer with JObject ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_MasksSensitiveFields()
        {
            JsonNode? parsed = JsonNode.Parse("{\"number\":\"4111111111111111\",\"merchantId\":\"test\"}");
            Assert.That(parsed, Is.Not.Null);

            logUtility.MaskSensitiveDataInJsonContainer(parsed);

            JsonNode? parsedNode1 = parsed!["number"];
            Assert.That(parsedNode1, Is.Not.Null);
            Assert.That(parsedNode1.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));

            JsonNode? parsedNode2 = parsed!["merchantId"];
            Assert.That(parsedNode2, Is.Not.Null);
            Assert.That(parsedNode2.ToString(), Is.EqualTo("test"));
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_HandlesNullValue()
        {
            JsonNode? parsed = JsonNode.Parse("{\"number\":null}");
            Assert.That(parsed, Is.Not.Null);

            logUtility.MaskSensitiveDataInJsonContainer(parsed);

            JsonNode? parsedNode1 = parsed!["number"];
            Assert.That(parsedNode1?.GetValue<JsonElement>().ValueKind, Is.Null);
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_MasksArrayUnderSensitiveProperty()
        {
            // When a sensitive property contains an array, the array elements should be masked
            JsonNode? parsed = JsonNode.Parse("{\"number\":[\"4111111111111111\",\"5500000000000004\"]}");
            Assert.That(parsed, Is.Not.Null);

            logUtility.MaskSensitiveDataInJsonContainer(parsed);

            JsonArray parsedArray = parsed["number"]!.AsArray();
            Assert.That(parsedArray, Is.Not.Null);

            JsonNode? parsedNode1 = parsedArray[0]!;
            Assert.That(parsedNode1, Is.Not.Null);
            Assert.That(parsedNode1.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));

            JsonNode? parsedNode2 = parsedArray[1]!;
            Assert.That(parsedNode2, Is.Not.Null);
            Assert.That(parsedNode2.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_DoesNotMaskArrayUnderNonSensitiveProperty()
        {
            // When a non-sensitive property contains an array of primitives, they stay unmasked
            JsonNode? parsed = JsonNode.Parse("{\"items\":[\"item1\",\"item2\"]}");
            Assert.That(parsed, Is.Not.Null);

            logUtility.MaskSensitiveDataInJsonContainer(parsed);

            JsonArray parsedArray = parsed["items"]!.AsArray();
            Assert.That(parsedArray, Is.Not.Null);

            JsonNode? parsedNode1 = parsedArray[0]!;
            Assert.That(parsedNode1, Is.Not.Null);
            Assert.That(parsedNode1.ToString(), Is.EqualTo("item1"));

            JsonNode? parsedNode2 = parsedArray[1]!;
            Assert.That(parsedNode2, Is.Not.Null);
            Assert.That(parsedNode2.ToString(), Is.EqualTo("item2"));
        }

        // --- MaskSensitiveDataInJsonContainer with JArray ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_SensitiveContext_MasksPrimitives()
        {
            JsonNode? parsed = JsonNode.Parse("[\"sensitive1\",\"sensitive2\",123]");
            Assert.That(parsed, Is.Not.Null);

            JsonArray parsedArray = parsed.AsArray();

            logUtility.MaskSensitiveDataInJsonContainer(parsedArray, isSensitiveContext: true);

            JsonNode? parsedNode1 = parsedArray[0]!;
            Assert.That(parsedNode1, Is.Not.Null);
            Assert.That(parsedNode1.ToString(), Is.EqualTo("XXXXXXXXXX"));

            JsonNode? parsedNode2 = parsedArray[1]!;
            Assert.That(parsedNode2, Is.Not.Null);
            Assert.That(parsedNode2.ToString(), Is.EqualTo("XXXXXXXXXX"));

            JsonNode? parsedNode3 = parsedArray[2]!;
            Assert.That(parsedNode3, Is.Not.Null);
            Assert.That(parsedNode3.ToString(), Is.EqualTo("XXXXX"));
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_NonSensitiveContext_DoesNotMaskPrimitives()
        {
            JsonNode? parsed = JsonNode.Parse("[\"value1\",\"value2\",456]");
            Assert.That(parsed, Is.Not.Null);

            JsonArray parsedArray = parsed.AsArray();

            logUtility.MaskSensitiveDataInJsonContainer(parsedArray, isSensitiveContext: false);

            JsonNode? parsedNode1 = parsedArray[0]!;
            Assert.That(parsedNode1, Is.Not.Null);
            Assert.That(parsedNode1.ToString(), Is.EqualTo("value1"));

            JsonNode? parsedNode2 = parsedArray[1]!;
            Assert.That(parsedNode2, Is.Not.Null);
            Assert.That(parsedNode2.ToString(), Is.EqualTo("value2"));

            JsonNode? parsedNode3 = parsedArray[2]!;
            Assert.That(parsedNode3, Is.Not.Null);
            Assert.That(parsedNode3.GetValue<int>(), Is.EqualTo(456));
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_MasksObjectElementsSensitiveFields()
        {
            JsonNode? parsed = JsonNode.Parse("[{\"number\":\"4111111111111111\",\"amount\":100}]");
            Assert.That(parsed, Is.Not.Null);

            JsonArray parsedArray = parsed.AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(parsedArray);

            JsonNode? parsedNode1 = parsedArray[0]!;
            Assert.That(parsedNode1, Is.Not.Null);
            Assert.Multiple(() =>
            {
                Assert.That(parsedNode1["number"]!.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));
                Assert.That(parsedNode1["amount"]!.GetValue<int>(), Is.EqualTo(100));
            });
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_NestedArrayInSensitiveContext()
        {
            JsonNode? parsed = JsonNode.Parse("[[\"nested1\",\"nested2\"]]");
            Assert.That(parsed, Is.Not.Null);

            JsonArray parsedArray = parsed.AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(parsedArray, isSensitiveContext: true);

            JsonNode? parsedNode1 = parsedArray[0]!;
            Assert.That(parsedNode1, Is.Not.Null);

            Assert.Multiple(() =>
            {
                Assert.That(parsedNode1[0]!.ToString(), Is.EqualTo("XXXXXXX"));
                Assert.That(parsedNode1[1]!.ToString(), Is.EqualTo("XXXXXXX"));
            });
        }

        // --- MLE prefix handling ---

        [Test]
        public void MaskSensitiveData_WithMlePrefix_StripsPrefixMasksAndReattaches()
        {
            string json = "{\"number\":\"4111111111111111\"}";
            string input = Constants.LOG_REQUEST_BEFORE_MLE + json;
            string result = logUtility.MaskSensitiveData(input);

            Assert.That(result, Is.Not.Null);

            Assert.That(result, Does.StartWith(Constants.LOG_REQUEST_BEFORE_MLE));
            string masked = result.Substring(Constants.LOG_REQUEST_BEFORE_MLE.Length);

            JsonNode? parsed = JsonNode.Parse(masked);
            Assert.That(parsed, Is.Not.Null);
            Assert.That(parsed["number"]!.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));
        }

        // --- Edge cases ---

        [Test]
        public void MaskSensitiveData_EmptyJsonObject_ReturnsEmptyObject()
        {
            string input = "{}";
            string result = logUtility.MaskSensitiveData(input);

            JsonObject parsed = JsonNode.Parse(result)!.AsObject();
            Assert.That(parsed, Is.Empty);
        }

        [Test]
        public void MaskSensitiveData_EmptyJsonArray_ReturnsEmptyArray()
        {
            string input = "[]";
            string result = logUtility.MaskSensitiveData(input);

            JsonArray parsed = JsonNode.Parse(result)!.AsArray();
            Assert.That(parsed, Is.Empty);
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_DeeplyNestedStructure()
        {
            string json = @"{
                ""orderInfo"": {
                    ""billTo"": {
                        ""firstName"": ""John"",
                        ""lastName"": ""Doe"",
                        ""email"": ""john@example.com""
                    },
                    ""amount"": ""100.00""
                }
            }";

            JsonObject obj = JsonNode.Parse(json)!.AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            JsonObject? billTo = obj["orderInfo"]!["billTo"] as JsonObject;
            Assert.That(billTo, Is.Not.Null);
            Assert.Multiple(() =>
            {
                Assert.That(billTo["firstName"]!.ToString(), Is.EqualTo("XXXX"));
                Assert.That(billTo["lastName"]!.ToString(), Is.EqualTo("XXX"));
                Assert.That(billTo["email"]!.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));
            });

            // amount is not in the sensitive list
            Assert.That(obj["orderInfo"]!["amount"]!.ToString(), Is.EqualTo("100.00"));
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_FloatInSensitiveContext()
        {
            JsonNode? parsed = JsonNode.Parse("[1.5, 2.7]");
            Assert.That(parsed, Is.Not.Null);

            JsonArray parsedArray = parsed.AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(parsedArray, isSensitiveContext: true);

            JsonNode? parsedNode1 = parsedArray[0];
            Assert.That(parsedNode1!.ToString(), Is.EqualTo("XXXXX"));

            JsonNode? parsedNode2 = parsedArray[1];
            Assert.That(parsedNode2!.ToString(), Is.EqualTo("XXXXX"));
        }

        [Test]
        public void MaskSensitiveData_MultipleSensitiveFields()
        {
            string input = "{\"number\":\"4111111111111111\",\"securityCode\":\"123\",\"expirationMonth\":\"12\",\"expirationYear\":\"2025\"}";
            string result = logUtility.MaskSensitiveData(input);

            JsonNode? parsed = JsonNode.Parse(result);
            Assert.That(parsed, Is.Not.Null);

            JsonObject parsedObject = parsed.AsObject();

            Assert.That(parsedObject["number"]!.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));
            Assert.That(parsedObject["securityCode"]!.ToString(), Is.EqualTo("XXX"));
            Assert.That(parsedObject["expirationMonth"]!.ToString(), Is.EqualTo("XX"));
            Assert.That(parsedObject["expirationYear"]!.ToString(), Is.EqualTo("XXXX"));
        }

        // --- Sensitive field with Object value ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_SensitiveFieldWithObjectValue_RecursesInto()
        {
            // "token" is a sensitive field; its value is an object — should recurse and mask inner sensitive fields
            JsonNode? parsed = JsonNode.Parse("{\"token\":{\"number\":\"4111\",\"merchantId\":\"test\"}}");
            Assert.That(parsed, Is.Not.Null);

            JsonObject parsedObject = parsed.AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(parsedObject);

            JsonObject? tokenObj = parsedObject["token"]! as JsonObject;
            Assert.That(tokenObj, Is.Not.Null);
            Assert.Multiple(() =>
            {
                Assert.That(tokenObj["number"]!.ToString(), Is.EqualTo("XXXX"));
                Assert.That(tokenObj["merchantId"]!.ToString(), Is.EqualTo("test"));
            });
        }

        // --- Sensitive field with Float value ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_SensitiveFieldWithFloatValue()
        {
            JsonNode? parsed = JsonNode.Parse("{\"account\":3.14}");
            Assert.That(parsed, Is.Not.Null);

            JsonObject parsedObject = parsed.AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(parsedObject);

            Assert.That(parsedObject["account"]!.ToString(), Is.EqualTo("XXXXX"));
        }

        // --- Boolean value in sensitive field (no masking — no case handles it) ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_SensitiveFieldWithBooleanValue_NotMasked()
        {
            // Boolean type has no masking case — should be left untouched
            JsonNode? parsed = JsonNode.Parse("{\"token\":true}");
            Assert.That(parsed, Is.Not.Null);

            JsonObject parsedObject = parsed.AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(parsedObject);

            Assert.Multiple(() =>
            {
                Assert.That(parsedObject["token"]!.GetValue<JsonElement>().ValueKind, Is.EqualTo(JsonValueKind.True));
                Assert.That(parsedObject["token"]!.GetValue<bool>(), Is.EqualTo(true));
            });
        }

        // --- Array with mixed types in sensitive context ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_SensitiveContext_MixedTypes()
        {
            JsonNode? parsed = JsonNode.Parse("[\"secret\", 42, 3.14, true, null]");
            Assert.That(parsed, Is.Not.Null);

            JsonArray arr = parsed!.AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(arr, isSensitiveContext: true);

            Assert.That(arr[0]!.ToString(), Is.EqualTo("XXXXXX"));  // string masked
            Assert.That(arr[1]!.ToString(), Is.EqualTo("XXXXX"));   // integer masked
            Assert.That(arr[2]!.ToString(), Is.EqualTo("XXXXX"));   // float masked
            Assert.That(arr[3]!.GetValue<bool>(), Is.EqualTo(true));   // boolean untouched
            Assert.That(arr[4]?.GetValue<JsonElement>().ValueKind, Is.Null); // null untouched
        }

        // --- Nested array in non-sensitive context ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_NestedArrayInNonSensitiveContext()
        {
            JsonNode? parsed = JsonNode.Parse("[[\"value1\",\"value2\"]]");
            Assert.That(parsed, Is.Not.Null);

            JsonArray arr = parsed!.AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(arr, isSensitiveContext: false);

            JsonArray inner = (JsonArray)arr[0]!;
            Assert.That(inner[0]!.ToString(), Is.EqualTo("value1"));
            Assert.That(inner[1]!.ToString(), Is.EqualTo("value2"));
        }

        // --- Object inside array inside sensitive field ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_SensitiveArrayContainingObjects()
        {
            // "number" is sensitive, value is array of objects — recurse into objects
            JsonNode? parsed = JsonNode.Parse("{\"number\":[{\"email\":\"a@b.com\",\"city\":\"NYC\"}]}");
            Assert.That(parsed, Is.Not.Null);

            JsonObject obj = parsed!.AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            JsonObject inner = (JsonObject)((JsonArray)obj["number"]!)[0]!;
            Assert.That(inner["email"]!.ToString(), Is.EqualTo("XXXXXXX"));  // email is sensitive
            Assert.That(inner["city"]!.ToString(), Is.EqualTo("NYC"));         // city is not sensitive
        }

        // --- All MLE prefix variants ---

        [Test]
        public void MaskSensitiveData_WithAfterMlePrefix()
        {
            string json = "{\"securityCode\":\"999\"}";
            string input = Constants.LOG_REQUEST_AFTER_MLE + json;
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsTrue(result.StartsWith(Constants.LOG_REQUEST_AFTER_MLE));
            string masked = result.Substring(Constants.LOG_REQUEST_AFTER_MLE.Length);
            JsonNode? parsedNode = JsonNode.Parse(masked);
            Assert.That(parsedNode, Is.Not.Null);

            JsonObject parsed = parsedNode!.AsObject();
            Assert.That(parsed["securityCode"]!.ToString(), Is.EqualTo("XXX"));
        }

        [Test]
        public void MaskSensitiveData_WithNetworkResponseBeforeMlePrefix()
        {
            string json = "{\"number\":\"4111\"}";
            string input = Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION + json;
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsTrue(result.StartsWith(Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION));
            string masked = result.Substring(Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION.Length);
            JsonNode? parsedNode = JsonNode.Parse(masked);
            Assert.That(parsedNode, Is.Not.Null);

            JsonObject parsed = parsedNode!.AsObject();
            Assert.That(parsed["number"]!.ToString(), Is.EqualTo("XXXX"));
        }

        [Test]
        public void MaskSensitiveData_WithNetworkResponseAfterMlePrefix()
        {
            string json = "{\"email\":\"test@test.com\"}";
            string input = Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION + json;
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsTrue(result.StartsWith(Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION));
            string masked = result.Substring(Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION.Length);
            JsonNode? parsedNode = JsonNode.Parse(masked);
            Assert.That(parsedNode, Is.Not.Null);

            JsonObject parsed = parsedNode!.AsObject();
            Assert.That(parsed["email"]!.ToString(), Is.EqualTo("XXXXXXXXXXXXX"));
        }

        // --- Regex fallback: Signature header ---

        [Test]
        public void MaskSensitiveData_SignatureHeader_MasksKeyIdAndSignature()
        {
            // Format must match: Signature : keyid="...",<middle>, signature="..."
            string input = "Signature : keyid=\"merchant-123\",algorithm=\"HmacSHA256\" headers=\"host\", signature=\"abc123def=\"";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsTrue(result.Contains("XXXXX"));
            Assert.IsFalse(result.Contains("merchant-123"));
            Assert.IsFalse(result.Contains("abc123def="));
        }

        // --- Regex fallback: Bearer token ---

        [Test]
        public void MaskSensitiveData_BearerToken_MasksToken()
        {
            string input = "Authorization : Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsTrue(result.Contains("xxxxxxxxxxxxxxxx"));
            Assert.IsFalse(result.Contains("eyJhbGciOiJIUzI1NiJ9"));
        }

        // --- JSON primitive input (default: break → regex fallback) ---

        [Test]
        public void MaskSensitiveData_JsonPrimitive_FallsToRegex()
        {
            // A bare integer is valid JSON but hits default case
            string input = "42";
            string result = logUtility.MaskSensitiveData(input);

            // No regex matches, so returned as-is
            Assert.That(result, Is.EqualTo("42"));
        }

        [Test]
        public void MaskSensitiveData_JsonStringPrimitive_FallsToRegex()
        {
            // A bare quoted string is valid JSON but hits default case
            string input = "\"hello world\"";
            string result = logUtility.MaskSensitiveData(input);

            Assert.That(result, Is.EqualTo("\"hello world\""));
        }

        // --- Non-sensitive field with nested object containing sensitive fields ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_NonSensitiveParentWithSensitiveChildren()
        {
            JsonNode? parsed = JsonNode.Parse("{\"paymentInfo\":{\"cardNumber\":\"4111222233334444\",\"currency\":\"USD\"}}");
            Assert.That(parsed, Is.Not.Null);

            JsonObject obj = parsed!.AsObject();
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            JsonObject payment = (JsonObject)obj["paymentInfo"]!;
            Assert.That(payment["cardNumber"]!.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));
            Assert.That(payment["currency"]!.ToString(), Is.EqualTo("USD"));
        }

        // --- Non-sensitive array containing objects with sensitive fields ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_NonSensitiveContextWithObjectsContainingSensitiveFields()
        {
            JsonNode? parsed = JsonNode.Parse("[{\"firstName\":\"Alice\",\"id\":\"123\"}]");
            Assert.That(parsed, Is.Not.Null);

            JsonArray arr = parsed!.AsArray();
            logUtility.MaskSensitiveDataInJsonContainer(arr, isSensitiveContext: false);

            JsonObject element = (JsonObject)arr[0]!;
            Assert.That(element["firstName"]!.ToString(), Is.EqualTo("XXXXX"));  // firstName is sensitive
            Assert.That(element["id"]!.ToString(), Is.EqualTo("123"));            // id is not sensitive
        }

        // --- Date type masking ---

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_SensitiveFieldWithDateValue()
        {
            // Newtonsoft parses date-like strings as JTokenType.Date when they match date formats
            JsonObject obj = new JsonObject
            {
                ["expirationMonth"] = JsonValue.Create(new DateTime(2025, 12, 1))
            };
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            Assert.That(obj["expirationMonth"]!.ToString(), Is.EqualTo("XX-XX-XXXX"));
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JArray_DateInSensitiveContext()
        {
            JsonArray arr = new JsonArray { JsonValue.Create(new DateTime(2025, 6, 15)) };
            logUtility.MaskSensitiveDataInJsonContainer(arr, isSensitiveContext: true);

            Assert.That(arr[0]!.ToString(), Is.EqualTo("XX-XX-XXXX"));
        }

        [Test]
        public void MaskSensitiveDataInJsonContainer_JObject_NonSensitiveFieldWithDateValue_NotMasked()
        {
            JsonObject obj = new JsonObject
            {
                ["createdDate"] = JsonValue.Create(new DateTime(2025, 1, 1))
            };
            logUtility.MaskSensitiveDataInJsonContainer(obj);

            // "createdDate" is not in the sensitive list, so it should remain untouched
            Assert.That(obj["createdDate"]!.ToString(), Is.Not.EqualTo("XX-XX-XXXX"));
        }

        // --- Non-JSON payload masking (sensitiveTags regex) ---

        [Test]
        public void MaskSensitiveData_NonJson_MasksSensitiveFieldsInQuotedJson()
        {
            string input = "error: \"number\":\"4111111111111111\",\"securityCode\":\"123\"";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
            Assert.IsFalse(result.Contains("\"securityCode\":\"123\""));
            Assert.IsTrue(result.Contains("\"number\":\"\""));
            Assert.IsTrue(result.Contains("\"securityCode\":\"\""));
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksSpacedJson()
        {
            // "key" : "value" with spaces around the colon — valid JSON, goes through JSON masking path
            string input = "{ \"number\" : \"4111111111111111\", \"securityCode\" : \"123\" }";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
            Assert.IsFalse(result.Contains("\"securityCode\" : \"123\""));
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksXmlPayloads()
        {
            string input = "<response><number>4111111111111111</number><securityCode>123</securityCode></response>";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
            Assert.IsFalse(result.Contains("<securityCode>123</securityCode>"));
            Assert.IsTrue(result.Contains("<number></number>"));
            Assert.IsTrue(result.Contains("<securityCode></securityCode>"));
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksFormEncodedPayloads()
        {
            string input = "number=4111111111111111&securityCode=123&amount=100";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
            Assert.IsFalse(result.Contains("securityCode=123"));
            Assert.IsTrue(result.Contains("number=&") || result.Contains("number="));
            Assert.IsTrue(result.Contains("securityCode=&") || result.Contains("securityCode="));
            Assert.IsTrue(result.Contains("amount=100")); // non-sensitive field preserved
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksMultilinePayloads()
        {
            string input = "error occurred\n\"number\":\"4111111111111111\"\n\"securityCode\":\"123\"";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
            Assert.IsFalse(result.Contains("\"securityCode\":\"123\""));
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksUnquotedNumericPayloads()
        {
            // Numeric card number not quoted — invalid JSON, falls to non-JSON path
            string input = "invalid { \"number\":4111111111111111, \"securityCode\":\"123\" }";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
            Assert.IsFalse(result.Contains("\"securityCode\":\"123\""));
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksTruncatedQuotedPayloads()
        {
            // Stream cut mid-value — no closing quote. Must still mask the PAN.
            string input = "error chunk: \"number\":\"4111111111111111";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
        }

        [Test]
        public void MaskSensitiveData_NonJson_MasksTruncatedXmlPayloads()
        {
            string input = "<response><number>4111111111111111";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
        }

        // --- Luhn PAN detection in free text ---

        [Test]
        public void MaskSensitiveData_MasksBareLuhnValidPanInFreeText()
        {
            // HTML/plain-text gateway error page with an unlabeled PAN — caught by Luhn sweep.
            string input = "<html>Gateway error: card 4111111111111111 was declined.</html>";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111111111111111"));
        }

        [Test]
        public void MaskSensitiveData_MasksBarePanWithSeparatorsInFreeText()
        {
            string input = "Plain error: 4111-1111-1111-1111 invalid";
            string result = logUtility.MaskSensitiveData(input);

            Assert.IsFalse(result.Contains("4111-1111-1111-1111"));
            Assert.IsFalse(result.Contains("4111111111111111"));
        }

        [Test]
        public void MaskSensitiveData_DoesNotMaskNonLuhnLongDigitsInFreeText()
        {
            // Long numeric IDs that are not Luhn-valid (e.g. transaction IDs) must NOT be masked.
            string input = "Transaction id 1234567890123456 was processed";
            string result = logUtility.MaskSensitiveData(input);

            // 1234567890123456 is not Luhn-valid → preserved
            Assert.IsTrue(result.Contains("1234567890123456"));
        }

        // --- Sensitive field with array of strings (JSON path) ---

        [Test]
        public void MaskSensitiveData_MasksSensitiveFieldWithArrayOfStrings()
        {
            string input = "{\"firstName\":[\"John\",\"Jane\"],\"lastName\":[\"Doe\"],\"email\":[\"john@example.com\"]}";
            string result = logUtility.MaskSensitiveData(input);
            JsonNode? parsed = JsonNode.Parse(result);
            Assert.That(parsed, Is.Not.Null);

            JsonObject resultJson = parsed!.AsObject();

            Assert.That(resultJson["firstName"]![0]!.ToString(), Is.EqualTo("XXXX"));
            Assert.That(resultJson["firstName"]![1]!.ToString(), Is.EqualTo("XXXX"));
            Assert.That(resultJson["lastName"]![0]!.ToString(), Is.EqualTo("XXX"));
            Assert.That(resultJson["email"]![0]!.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));
        }

        [Test]
        public void MaskSensitiveData_MasksSensitiveFieldWithNestedArrayOfStrings()
        {
            string input = "{\"email\":[[\"john@example.com\",\"jane@example.com\"]]}";
            string result = logUtility.MaskSensitiveData(input);
            JsonNode? parsed = JsonNode.Parse(result);
            Assert.That(parsed, Is.Not.Null);

            JsonObject resultJson = parsed!.AsObject();

            Assert.That(resultJson["email"]![0]![0]!.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));
            Assert.That(resultJson["email"]![0]![1]!.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));
        }

        [Test]
        public void MaskSensitiveData_DoesNotMaskNonSensitiveArrayStrings()
        {
            string input = "{\"amount\":[\"100\",\"200\"],\"currency\":\"USD\"}";
            string result = logUtility.MaskSensitiveData(input);
            JsonNode? parsed = JsonNode.Parse(result);
            Assert.That(parsed, Is.Not.Null);

            JsonObject resultJson = parsed!.AsObject();

            Assert.That(resultJson["amount"]![0]!.ToString(), Is.EqualTo("100"));
            Assert.That(resultJson["amount"]![1]!.ToString(), Is.EqualTo("200"));
            Assert.That(resultJson["currency"]!.ToString(), Is.EqualTo("USD"));
        }

        // --- Deeply nested arrays in JSON ---

        [Test]
        public void MaskSensitiveData_MasksSensitiveFieldsInsideArrayObjects()
        {
            string input = "{\"paymentInstruments\":[{\"card\":{\"number\":\"4111111111111111\",\"securityCode\":\"123\"}}]}";
            string result = logUtility.MaskSensitiveData(input);
            JsonNode? parsed = JsonNode.Parse(result);
            Assert.That(parsed, Is.Not.Null);

            JsonObject resultJson = parsed!.AsObject();

            Assert.That(resultJson["paymentInstruments"]![0]!["card"]!["number"]!.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));
            Assert.That(resultJson["paymentInstruments"]![0]!["card"]!["securityCode"]!.ToString(), Is.EqualTo("XXX"));
        }

        [Test]
        public void MaskSensitiveData_MasksSensitiveFieldsInNestedArrays()
        {
            string input = "{\"groups\":[[{\"number\":\"5555555555554444\",\"securityCode\":\"123\"}]]}";
            string result = logUtility.MaskSensitiveData(input);
            JsonNode? parsed = JsonNode.Parse(result);
            Assert.That(parsed, Is.Not.Null);

            JsonObject resultJson = parsed!.AsObject();

            Assert.That(resultJson["groups"]![0]![0]!["number"]!.ToString(), Is.EqualTo("XXXXXXXXXXXXXXXX"));
            Assert.That(resultJson["groups"]![0]![0]!["securityCode"]!.ToString(), Is.EqualTo("XXX"));
        }

        // --- ConvertDictionaryToStringWithMasking ---

        [Test]
        public void ConvertDictionaryToStringWithMasking_MasksSensitiveKeys()
        {
            var dict = new Dictionary<string, string>
            {
                { "number", "4111111111111111" },
                { "merchantId", "testMerchant" }
            };

            string result = logUtility.ConvertDictionaryToStringWithMasking(dict);

            Assert.IsTrue(result.Contains("number = ***"));
            Assert.IsTrue(result.Contains("merchantId = testMerchant"));
            Assert.IsFalse(result.Contains("4111111111111111"));
        }

        [Test]
        public void ConvertDictionaryToStringWithMasking_DisabledMasking_ShowsAllValues()
        {
            var dict = new Dictionary<string, string>
            {
                { "number", "4111111111111111" },
                { "merchantId", "testMerchant" }
            };

            string result = logUtility.ConvertDictionaryToStringWithMasking(dict, maskSensitiveData: false);

            Assert.IsTrue(result.Contains("number = 4111111111111111"));
            Assert.IsTrue(result.Contains("merchantId = testMerchant"));
        }

        [Test]
        public void ConvertDictionaryToString_MasksByDefault()
        {
            var dict = new Dictionary<string, string>
            {
                { "number", "4111111111111111" },
                { "amount", "100" }
            };

            string result = logUtility.ConvertDictionaryToString(dict);

            Assert.IsTrue(result.Contains("number = ***"));
            Assert.IsTrue(result.Contains("amount = 100"));
            Assert.IsFalse(result.Contains("4111111111111111"));
        }
    }
}
