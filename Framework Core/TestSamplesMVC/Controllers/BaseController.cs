using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;
using TravelAce.InTravel.WebAdmin.Helpers;
using TravelAce.InTravel.Common.Helper;

namespace TravelAce.InTravel.WebAdmin.Controllers
{
    [Authorize]
    public abstract class BaseController : Controller
    {
       protected override JsonResult Json(object data, string contentType,
       Encoding contentEncoding, JsonRequestBehavior behavior)
        {
            return new JsonNetResult
            {
                Data = data,
                ContentType = contentType,
                ContentEncoding = contentEncoding,
                JsonRequestBehavior = behavior
            };
        }

        //Para nao dar erro de DataReader
        // Colocar na Con String : MultipleActiveResultSets=True"
        //<connectionStrings>
        //    <add name="dbIntravelContext" connectionString="Data Source=OMER;Initial Catalog=dbIntravel;Persist Security Info=True;User ID=intravel;Password=87Yheo3W;MultipleActiveResultSets=True"
        //    providerName="System.Data.SqlClient" />
        //</connectionStrings>

    }
}
