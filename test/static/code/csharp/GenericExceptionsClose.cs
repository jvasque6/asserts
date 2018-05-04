using System;

public class GenericExceptionsClose
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
      Console.WriteLine("Warning: ArithmeticException");
    }

    catch(IndexOutOfRangeException e)
    {
      Console.WriteLine("Warning: ArrayIndexOutOfBoundsException");
    }
/*
    try
    {
      Console.WriteLine("Out of try-catch block...");
    }

    catch(Exception e)
    {
      Console.WriteLine("Warning: Some Other exception");
    }
*/
  }
}
