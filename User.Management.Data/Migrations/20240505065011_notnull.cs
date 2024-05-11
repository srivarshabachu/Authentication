using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace User.Management.Data.Migrations
{
    /// <inheritdoc />
    public partial class notnull : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "18f453a2-d800-41b0-a346-51d2eb498fb3");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "9ba76088-8187-4c49-bfee-dacaf9b0d3c1");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "9f9b4376-66e5-4937-afbd-9d56fa6fdea9");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "2146162d-6c9a-4a8c-a44d-4ad794f5c0ff", "1", "Admin", "Admin" },
                    { "7adc4484-970b-4844-83ee-6873d73ef8db", "2", "User", "User" },
                    { "8184ae62-8542-4506-bc7d-5e3906f3326c", "3", "HR", "HR" }
                });
        }
    }
}
