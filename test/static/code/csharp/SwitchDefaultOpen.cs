using System;

public class SwitchDefaultOpen{
   public static void Main()
   {
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
