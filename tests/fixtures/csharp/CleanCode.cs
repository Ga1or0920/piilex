using System;

namespace Example
{
    public class Calculator
    {
        public int Count { get; set; }

        public int Add(int a, int b)
        {
            return a + b;
        }

        public void Display()
        {
            Console.WriteLine("Count: " + Count);
        }
    }
}
