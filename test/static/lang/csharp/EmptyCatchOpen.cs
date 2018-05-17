using System;

public class Example
{
    public static void Main()
    {
        try
        {
            int[] a = new int[7];
            a[4]=30/0;
            Console.WriteLine("First print statement in try block");
        }

        catch(ArithmeticException e)
        {

        }

        catch(IndexOutOfRangeException e)
        {
            // Oneline comment
        }

        catch(Exception e)
        {
            /*
            Multiline comment
            Test
            */
        }
    }
/*
    try
    {
        Console.WriteLine("Out of try-catch block...");
        catch(Exception e)
        {
            Console.WriteLine("Warning: Some Other exception");
        }
*/
}
