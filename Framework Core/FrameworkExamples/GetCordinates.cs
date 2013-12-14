 
//Método que consulta o banco de dados e retorna em endereco pro extenso, 
//e chama o metodo //GetCoordinates(region) passando o valor extraido do banco como parametro

//Variaveis Publicas
public string region = "";
public static string Coordenada = ""; //linkada com: title: '<%=region %>, <%= Coordenada %>', var latlng = new google.maps.LatLng(<%=Coordenada %>);

 private void ConsultaEndereco()
        {
            string I_Movel = Request.QueryString["DataI"];

            ClassLibrary.Imoveis end = new ClassLibrary.Imoveis();
            end.Load(I_Movel);

            // Doutor Cardoso de Melo, 585 - Vila Olimpia, SP, São Paulo  
            //region = end.Endereco + " - " + end.Bairro + " , " + end.Estado + " , " + end.Cidade; 
            region = end.Endereco + " - " + end.Bairro + ", " + end.Cidade;
            lblEndereco.InnerText = region;
            try
            {
                GetCoordinates(region);
            }
            catch (Exception ex)
            {

            }
        }

        //Recebe o parametro region(endereco), do metodo Consulta endereco e se conecta a uri e extrai as informações via XML,
        // ent~]ao recebe a resposta.. e trata as informações, já com geocode reverso.
        public static Coordinate GetCoordinates(string region)
        {
            string Latitude = "";
            string Longitude = "";
            string FormattedAddress = "";
            string LocationType = "";

            // Envia o endereco para a url retornando uma resposta em XML 
            //http://maps.googleapis.com/maps/api/geocode/xml?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&sensor=true_or_false

            string uri = "http://maps.googleapis.com/maps/api/geocode/xml?address=" + region + "&sensor=true";

            WebResponse response = null;
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
                request.Method = "GET";
                response = request.GetResponse();
                if (response != null)
                {
                    XPathDocument document = new XPathDocument(response.GetResponseStream());
                    XPathNavigator navigator = document.CreateNavigator();

                    // get response status
                    XPathNodeIterator statusIterator = navigator.Select("/GeocodeResponse/status");
                    while (statusIterator.MoveNext())
                    {
                        if (statusIterator.Current.Value != "OK")
                        {
                            Console.WriteLine("Error: Response status = '" + statusIterator.Current.Value + "'");
                            break;
                        }
                    }
                    // GET RESULTS  
                    XPathNodeIterator resultIterator = navigator.Select("/GeocodeResponse/result");
                    while (resultIterator.MoveNext())
                    {
                        

                        XPathNodeIterator formattedAddressIterator = resultIterator.Current.Select("formatted_address");
                        while (formattedAddressIterator.MoveNext())
                        {
                            FormattedAddress = formattedAddressIterator.Current.Value;
                        }

                        XPathNodeIterator geometryIterator = resultIterator.Current.Select("geometry");
                        while (geometryIterator.MoveNext())
                        {
                           

                            XPathNodeIterator locationIterator = geometryIterator.Current.Select("location");
                            while (locationIterator.MoveNext())
                            {
                                

                                XPathNodeIterator latIterator = locationIterator.Current.Select("lat");
                                while (latIterator.MoveNext())
                                {
                                    Latitude = latIterator.Current.Value;
                                    
                                }

                                XPathNodeIterator lngIterator = locationIterator.Current.Select("lng");
                                while (lngIterator.MoveNext())
                                {
                                    Longitude = lngIterator.Current.Value;
                                    
                                }
                            }

                            XPathNodeIterator locationTypeIterator = geometryIterator.Current.Select("location_type");
                            while (locationTypeIterator.MoveNext())
                            {
                                LocationType = locationTypeIterator.Current.Value;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                Console.WriteLine("Clean up");
                if (response != null)
                {
                    response.Close();
                    response = null;
                }
            }

            //Após extraido as infomações, retorna as mesma para o metodo Coordinate(Lat, Long), que formata a lat e long, no padrão exigido pelo google.
            return new Coordinate(Convert.ToDouble(Latitude), Convert.ToDouble(Longitude));
        }

        public struct Coordinate
        {
            
            private double lat;
            private double lng;

            public Coordinate(double latitude, double longitude)
            {
                lat = latitude;
                lng = longitude;
                Coordenada = String.Format(@"{0:00\.0000000}", lat) + ", " + String.Format(@"{0:00\.0000000}", lng);

            }

            public double Latitude { get { return lat; } set { lat = value; } }
            public double Longitude { get { return lng; } set { lng = value; } }

        }


        //Retirar da classe e colcoar em uma pagina .ASPX e C# code-behind

        //Stylesheet para o mapa
        <style type="text/css">
            #map_canvas {
                height: 100%;
            }
        </style>
        // Se quiser calcular a rota so acresentar a div -html abaixo
        <div class="span4" style="height: 100px; background-color: #009CE1; color: #ffffff;">
            <p style="margin-top: 18px; margin-left: 20px;">Faça sua Rota<input type="text" id="startvalue" style="margin-left: 25px;" /></p>
                <p style="margin-left: 20px;">
                            Ex: Rua Pio XI, 55, São Paulo
                        <asp:Button ID="calcular" runat="server" Text="Como Chegar" OnClientClick="return calcRoute()" Style="margin-left: 45px; margin-top: 3px;" CssClass="btn-warning" />
                </p>
        </div>
        //HTML Map-div
        <div class="thumbnail" id="map_canvas" style="height: 245px; width: 560px;"></div>

        //Script que recebe as corrdenadas extraidas do banco de dados.

    <%--Inicializar o mapa--%>

    <script type="text/javascript" src="https://maps.google.com/maps/api/js?sensor=true"></script>
    <%-- <script type="text/javascript" src="https://maps.googleapis.com/maps/api/js?key=AIzaSyBsXBKzjHJc2wYAwwZirITFOpI5f5T6eFw&sensor=true"></script>--%>
    <script type="text/javascript">
        var directionDisplay;
        var directionsService = new google.maps.DirectionsService();
        //var latlng = new google.maps.LatLng(-23.53243, -46.665126);
        var latlng = new google.maps.LatLng(<%=Coordenada %>);

        function initialize() {
            directionDisplay = new google.maps.DirectionsRenderer();

            var mapOptions = {
                center: latlng,
                zoom: 16,
                mapTypeId: google.maps.MapTypeId.ROADMAP
            };

            var map = new google.maps.Map(document.getElementById("map_canvas"),
                mapOptions);

            var marker = new google.maps.Marker
            (
                   {
                       position: latlng,
                       map: map,
                       title: '<%=region %>, <%= Coordenada %>',
                       animation: google.maps.Animation.DROP

                   }
            );

                   directionDisplay.setMap(map);
                   directionsRenderer.setPanel(document.getElementById("panel"));

               }

               function calcRoute() {

                   var start = document.getElementById('startvalue').value;
                   var end = latlng;
                   var request = {
                       origin: start,
                       destination: end,
                       travelMode: google.maps.DirectionsTravelMode.DRIVING
                   };
                   directionsService.route(request, function (response, status) {
                       if (status == google.maps.DirectionsStatus.OK) {
                           directionDisplay.setDirections(response);
                       }
                   });
                   return false;
               }

               function toggleBounce() {

                   if (marker.getAnimation() != null) {
                       marker.setAnimation(null);
                   } else {
                       marker.setAnimation(google.maps.Animation.BOUNCE);
                   }
               }

    </script>