using System;
using System.Collections.Generic;
using System.Diagnostics;
using Reloaded.Injector.Interop;
using Reloaded.Injector.Interop.Structures;

namespace Reloaded.Injector
{
    public static class Safety
    {
        /// <summary>
        /// Waits for the modules to initialize in a target process.
        /// See remarks of EnumProcessModulesEx for details.
        /// </summary>
        public static List<Module> TryGetModules(Process targetProcess, int timeout = 1000)
        {
            List<Module> modules = new List<Module>();
            Stopwatch watch = new Stopwatch();
            watch.Start();

            while (watch.ElapsedMilliseconds < timeout)
            {
                try
                {
                    modules = ModuleCollector.CollectModules(targetProcess);
                    break;
                }
                catch { /* ignored */ }
            }
            
            if (modules.Count == 0)
                throw new Exception($"Failed to find information on any of the modules inside the process " +
                                    $"using EnumProcessModulesEx within the { timeout } millisecond timeout. " +
                                    "The process has likely not yet initialized.");

            return modules;
        }
    }
}
