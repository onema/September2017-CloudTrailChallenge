using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;
using Amazon.Lambda.Core;
using Amazon.Lambda.SNSEvents;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;
using CloudTrailer.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;


// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace CloudTrailer
{
    public class CloudTrailModel {
        public string s3Bucket { get; set; }
        public List<string> s3ObjectKey { get; set; }
    }
    
    public class Function
    {
        private static readonly byte[] GZipHeaderBytes = {0x1f, 0x8b};
//        private static readonly byte[] GZipHeaderBytes = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 4, 0};

        private IAmazonS3 S3Client { get; }
        private IAmazonSimpleNotificationService SnsClient { get; }
        private IAmazonIdentityManagementService IamClient { get; }
        private static string AlertTopicArn => Environment.GetEnvironmentVariable("AlertTopicArn");

        /// <summary>
        /// Default constructor. This constructor is used by Lambda to construct the instance. When invoked in a Lambda environment
        /// the AWS credentials will come from the IAM role associated with the function and the AWS region will be set to the
        /// region the Lambda function is executed in.
        /// </summary>
        public Function()
        {
            S3Client = new AmazonS3Client();
            SnsClient = new AmazonSimpleNotificationServiceClient();
            IamClient = new AmazonIdentityManagementServiceClient();
        }

        public async Task FunctionHandler(SNSEvent snsEvent, ILambdaContext context)
        {
            // ### Level 1 - Create New Trail and Configure Lambda
            context.Logger.LogLine(JsonConvert.SerializeObject(snsEvent));

            
            // ### Level 2 - Retrieve Logs from S3
            var crMessage = JsonConvert.DeserializeObject<CloudTrailModel>(snsEvent.Records.First().Sns.Message);
            var bucketName = crMessage.s3Bucket;
            var fileNames = crMessage.s3ObjectKey;
            var records = new HashSet<CloudTrailEvent>();
            foreach (string fileName in fileNames) {
                var response = S3Client.GetObjectAsync(
                    new GetObjectRequest {
                        BucketName = bucketName, 
                        Key = fileName
                    }).Result;
                var fileBytes = ReadStream(response.ResponseStream);
                var record = ExtractCloudTrailRecordsAsync(context.Logger, fileBytes).Result;
                foreach (var cloudTrailEvent in record.Records) {
                    records.Add(cloudTrailEvent);
                }
                context.Logger.LogLine(record.Records.First().EventName);
            };
            
            // ### Level 3 - Filter for specific events and send alerts
            var createUserEvents = records.Where(x => x.EventName == "CreateUser");
            await SnsClient.PublishAsync(new PublishRequest {
                Message = JsonConvert.SerializeObject(createUserEvents),
                TopicArn = "arn:aws:sns:us-west-2:065150860170:test"
            });

            // ### Boss level - Take mitigating action
            foreach (var userEvent in createUserEvents) {
                var username = userEvent.RequestParameters["userName"] as String;
                context.Logger.LogLine($"Deleting user: {username}");
                await IamClient.DeleteUserAsync(new DeleteUserRequest {
                    UserName = username
                });
            }
        }


        private async Task<CloudTrailRecords> ExtractCloudTrailRecordsAsync(ILambdaLogger logger, byte[] input)
        {
            var appearsGzipped = ResponseAppearsGzipped(input);
            logger.LogLine($"Input appears to be gzipped: {appearsGzipped}");
            if (appearsGzipped)
            {
                using (var contents = new MemoryStream())
                using (var gz = new GZipStream(new MemoryStream(input), CompressionMode.Decompress))
                {
                    await gz.CopyToAsync(contents);
                    input = contents.ToArray();
                }
            }

            var serializedRecords = Encoding.UTF8.GetString(input);
            logger.Log(serializedRecords);
            return JsonConvert.DeserializeObject<CloudTrailRecords>(serializedRecords);

            bool ResponseAppearsGzipped(byte[] bytes)
            {
                var header = new byte[GZipHeaderBytes.Length];
                Array.Copy(bytes, header, header.Length);
                return header.SequenceEqual(GZipHeaderBytes);
            }
        }
        
        private static byte[] ReadStream(Stream responseStream)
        {
            byte[] buffer = new byte[16 * 1024];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while ((read = responseStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }
    }
}