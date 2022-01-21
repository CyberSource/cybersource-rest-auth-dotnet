using System.Collections.Generic;
using System.Threading.Tasks;
using AuthenticationSdk.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NLog;

namespace AuthenticationSdkTests
{
    [TestClass]
    public class UnitTest1
    {
        private Logger logger = LogManager.GetCurrentClassLogger();

        [TestMethod]
        public void SingleThreadedLogging()
        {
            LogUtility logUtility = new LogUtility();
            string result = logUtility.MaskSensitiveData("foo");

            Assert.AreEqual("foo", result);

        }


        /// <summary>
        /// Ensure that MaskSensitive Data is thread safe
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public async Task MultiThreadedLogging()
        {
            LogUtility logUtility = new LogUtility();
            int taskCount = 100;

            List<Task> tasks = new List<Task>();
            for (int i = 0; i < taskCount; i++)
            {
                tasks.Add(new Task(() =>
                {
                    for (int j = 0; j < 100; j++)
                    {
                        var r = logUtility.MaskSensitiveData("foo");
                        Assert.AreEqual("foo", r);
                    }
                }));
            }

            foreach (var task in tasks)
            {
                task.Start();
            }

            await Task.WhenAll(tasks);
        }


        /// <summary>
        /// Ensure IsMaskingEnabled does not throw exceptions
        /// </summary>
        [TestMethod]
        public void MaskSenstiveDataSetting()
        {
            LogUtility logUtility = new LogUtility();
            Assert.IsTrue(logUtility.IsMaskingEnabled(logger));
        }
    }
}
