using System;

public class SwitchDefaultOpen{
   public static void Main()
   {

      byte[] bytes1 = new byte[100];
      byte[] bytes2 = new byte[100];
      Random rnd1 = new Random();
      Random rnd2 = new Random();

      rnd1.NextBytes(bytes1);
      rnd2.NextBytes(bytes2);

      string monthString;
      switch (month)
      {
         case 1:
            monthString = "January";
            break;
         case 12:
            monthString = "December";
            break;
      }

      switch (month)
      {
         case 1:
            monthString = "January";
            break;
         case 12:
            monthString = "December";
            break;
         /*
         default:
            monthString = "Invalid month";
            break;
         */
      }

      switch (month)
      {
         case 1:
            monthString = "January";
            break;
         case 12:
            monthString = "December";
            break;
         //default:
            //monthString = "Invalid month";
                  //break;
      }
   }
}