using System;
using Reloaded.Injector.Shared;
using Xunit;

namespace Reloaded.Injector.Tests.X64;

public class HelloWorld : IClassFixture<HelloWorldFixture>, IDisposable
{
    private const string InjectModule64     = "Reloaded.Injector.Tests.Dll64.dll";
    private const string InjectModule32     = "Reloaded.Injector.Tests.Dll32.dll";
    private const string CalculatorAdd      = "Add";
    private const string CalculatorSubtract = "Subtract";
    private const string CalculatorMultiply = "Multiply";
    private const string CalculatorDivide   = "Divide";

    /* For testing on low end hardware. Reduce this value for faster tests. */
    private const int XLoops = 15;
    private const int YLoops = 15;

    private readonly HelloWorldFixture _helloWorldFixture;

    public HelloWorld(HelloWorldFixture helloWorldFixture)
    {
        _helloWorldFixture = helloWorldFixture;
    }
    
    public void Dispose()
    {
        _helloWorldFixture?.Dispose();
    }
        
    /* Shellcode Test */

    [Fact]
    public void GetFunctionAddress64()
    {
        var addAddress    = _helloWorldFixture.Injector64.GetFunctionAddress(InjectModule64, CalculatorAdd);
        var subAddress    = _helloWorldFixture.Injector64.GetFunctionAddress(InjectModule64, CalculatorSubtract);
        var mulAddress    = _helloWorldFixture.Injector64.GetFunctionAddress(InjectModule64, CalculatorMultiply);
        var divAddress    = _helloWorldFixture.Injector64.GetFunctionAddress(InjectModule64, CalculatorDivide);

        Assert.NotEqual(0, addAddress);
        Assert.NotEqual(0, subAddress);
        Assert.NotEqual(0, mulAddress);
        Assert.NotEqual(0, divAddress);
    }

    [Fact]
    public void GetFunctionAddress32()
    {
        var addAddress = _helloWorldFixture.Injector32.GetFunctionAddress(InjectModule32, CalculatorAdd);
        var subAddress = _helloWorldFixture.Injector32.GetFunctionAddress(InjectModule32, CalculatorSubtract);
        var mulAddress = _helloWorldFixture.Injector32.GetFunctionAddress(InjectModule32, CalculatorMultiply);
        var divAddress = _helloWorldFixture.Injector32.GetFunctionAddress(InjectModule32, CalculatorDivide);

        Assert.NotEqual(0, addAddress);
        Assert.NotEqual(0, subAddress);
        Assert.NotEqual(0, mulAddress);
        Assert.NotEqual(0, divAddress);
    }

    /* Calculator Test */

    [Fact]
    public void Add64()
    {
        for (int x = 0; x < XLoops; x++)
        {
            for (int y = YLoops; y > 0; y--)
            {
                int expected = x + y;
                int result   = _helloWorldFixture.Injector64.CallFunction(InjectModule64, CalculatorAdd, new TwoNumbers(x, y));

                Assert.Equal(expected, result);
            }
        }
    }

    [Fact]
    public void Add32()
    {
        for (int x = 0; x < XLoops; x++)
        {
            for (int y = YLoops; y > 0; y--)
            {
                int expected = x + y;
                int result = _helloWorldFixture.Injector32.CallFunction(InjectModule32, CalculatorAdd, new TwoNumbers(x, y));

                Assert.Equal(expected, result);
            }
        }
    }

    [Fact]
    public void Subtract64()
    {
        for (int x = 0; x < XLoops; x++)
        {
            for (int y = YLoops; y > 0; y--)
            {
                int expected = x - y;
                int result = _helloWorldFixture.Injector64.CallFunction(InjectModule64, CalculatorSubtract, new TwoNumbers(x, y));

                Assert.Equal(expected, result);
            }
        }
    }

    [Fact]
    public void Subtract32()
    {
        for (int x = 0; x < XLoops; x++)
        {
            for (int y = YLoops; y > 0; y--)
            {
                int expected = x - y;
                int result = _helloWorldFixture.Injector32.CallFunction(InjectModule32, CalculatorSubtract, new TwoNumbers(x, y));

                Assert.Equal(expected, result);
            }
        }
    }

    [Fact]
    public void Multiply64()
    {
        for (int x = 0; x < XLoops; x++)
        {
            for (int y = YLoops; y > 0; y--)
            {
                int expected = x * y;
                int result = _helloWorldFixture.Injector64.CallFunction(InjectModule64, CalculatorMultiply, new TwoNumbers(x, y));

                Assert.Equal(expected, result);
            }
        }
    }

    [Fact]
    public void Multiply32()
    {
        for (int x = 0; x < XLoops; x++)
        {
            for (int y = YLoops; y > 0; y--)
            {
                int expected = x * y;
                int result = _helloWorldFixture.Injector32.CallFunction(InjectModule32, CalculatorMultiply, new TwoNumbers(x, y));

                Assert.Equal(expected, result);
            }
        }
    }

    [Fact]
    public void Divide64()
    {
        for (int x = 0; x < XLoops; x++)
        {
            for (int y = YLoops; y > 0; y--)
            {
                int expected = x / y;
                int result = _helloWorldFixture.Injector64.CallFunction(InjectModule64, CalculatorDivide, new TwoNumbers(x, y));

                Assert.Equal(expected, result);
            }
        }
    }

    [Fact]
    public void Divide32()
    {
        for (int x = 0; x < XLoops; x++)
        {
            for (int y = YLoops; y > 0; y--)
            {
                int expected = x / y;
                int result = _helloWorldFixture.Injector32.CallFunction(InjectModule32, CalculatorDivide, new TwoNumbers(x, y));

                Assert.Equal(expected, result);
            }
        }
    }

    [Fact]
    public void All64()
    {
        for (int x = 0; x < XLoops; x++)
        {
            for (int y = YLoops; y > 0; y--)
            {
                int addExpected = x + y;
                int subExpected = x - y;
                int mulExpected = x * y;
                int divExpected = x / y;

                int addResult = _helloWorldFixture.Injector64.CallFunction(InjectModule64, CalculatorAdd, new TwoNumbers(x, y));
                int subResult = _helloWorldFixture.Injector64.CallFunction(InjectModule64, CalculatorSubtract, new TwoNumbers(x, y));
                int mulResult = _helloWorldFixture.Injector64.CallFunction(InjectModule64, CalculatorMultiply, new TwoNumbers(x, y));
                int divResult = _helloWorldFixture.Injector64.CallFunction(InjectModule64, CalculatorDivide, new TwoNumbers(x, y));

                Assert.Equal(addExpected, addResult);
                Assert.Equal(subExpected, subResult);
                Assert.Equal(mulExpected, mulResult);
                Assert.Equal(divExpected, divResult);
            }
        }
    }


    [Fact]
    public void All32()
    {
        for (int x = 0; x < XLoops; x++)
        {
            for (int y = YLoops; y > 0; y--)
            {
                int addExpected = x + y;
                int subExpected = x - y;
                int mulExpected = x * y;
                int divExpected = x / y;

                int addResult = _helloWorldFixture.Injector32.CallFunction(InjectModule32, CalculatorAdd, new TwoNumbers(x, y));
                int subResult = _helloWorldFixture.Injector32.CallFunction(InjectModule32, CalculatorSubtract, new TwoNumbers(x, y));
                int mulResult = _helloWorldFixture.Injector32.CallFunction(InjectModule32, CalculatorMultiply, new TwoNumbers(x, y));
                int divResult = _helloWorldFixture.Injector32.CallFunction(InjectModule32, CalculatorDivide, new TwoNumbers(x, y));

                Assert.Equal(addExpected, addResult);
                Assert.Equal(subExpected, subResult);
                Assert.Equal(mulExpected, mulResult);
                Assert.Equal(divExpected, divResult);
            }
        }
    }
}