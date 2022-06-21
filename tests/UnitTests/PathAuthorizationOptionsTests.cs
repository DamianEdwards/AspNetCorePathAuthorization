using AspNetCore.Authorization.PathBased;
using Microsoft.AspNetCore.Authorization;

namespace UnitTests;

public class PathAuthorizationOptionsTests
{
    public static IEnumerable<object[]> GetPathList() => new List<object[]>
    {
        new[] { "/" },
        new[] { "/a" },
        new[] { "/a/b" },
        new[] { "/a/b/c" },
        new[] { "/a/b/c/d" },
        new[] { "/d" },
        new[] { "/b/a" },
        new[] { "/c/b/a" },
        new[] { "/d/c/b/a" },
    };

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_UsesDefaultPolicy(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var options = new PathAuthorizationOptions();

        options.AuthorizePath(path);

        var root = options.BuildMappingTree(authzOptions);
        var (policy, _) = root.GetAuthorizationDataForPath(path);

        Assert.Equal(authzOptions.DefaultPolicy, policy);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_UsesSuppliedPolicyBuilderDelegate(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var options = new PathAuthorizationOptions();
        var delegateCalled = false;
        Action<AuthorizationPolicyBuilder> configurePolicy = builder =>
        {
            builder.RequireRole("TestRole");
            delegateCalled = true;
        };
        var expectedPolicyBuilder = new AuthorizationPolicyBuilder();
        configurePolicy(expectedPolicyBuilder);
        var expectedPolicy = expectedPolicyBuilder.Build();

        options.AuthorizePath(path, configurePolicy);

        var root = options.BuildMappingTree(authzOptions);
        var (policy, _) = root.GetAuthorizationDataForPath(path);

        Assert.True(delegateCalled);
        Assert.NotNull(policy);
        Assert.Equal(expectedPolicy.Requirements.Count, policy!.Requirements.Count);
        for (int i = 0; i < expectedPolicy.Requirements.Count; i++)
        {
            Assert.IsType(expectedPolicy.Requirements[i].GetType(), policy!.Requirements[i]);
        }
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_UsesSuppliedPolicyInstance(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var options = new PathAuthorizationOptions();
        var policyBuilder = new AuthorizationPolicyBuilder();
        policyBuilder.RequireRole("TestRole");
        var expectedPolicy = policyBuilder.Build();

        options.AuthorizePath(path, expectedPolicy);

        var root = options.BuildMappingTree(authzOptions);
        var (policy, _) = root.GetAuthorizationDataForPath(path);

        Assert.NotNull(policy);
        Assert.Equal(expectedPolicy, policy);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_UsesSuppliedPolicyName(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var policyBuilder = new AuthorizationPolicyBuilder();
        policyBuilder.RequireRole("TestRole");
        var expectedPolicy = policyBuilder.Build();
        authzOptions.AddPolicy("TestPolicy", expectedPolicy);
        var options = new PathAuthorizationOptions();

        options.AuthorizePath(path, "TestPolicy");

        var root = options.BuildMappingTree(authzOptions);
        var (policy, _) = root.GetAuthorizationDataForPath(path);

        Assert.NotNull(policy);
        Assert.Equal(expectedPolicy, policy);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_ThrowsInvalidOperationException_IfSuppliedPolicyNameIsNotDefined(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var options = new PathAuthorizationOptions();

        options.AuthorizePath(path, "NonExistentPolicy");

        Assert.Throws<InvalidOperationException>(() =>
        {
            var root = options.BuildMappingTree(authzOptions);
        });
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_SetsAllowAnonymous(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var options = new PathAuthorizationOptions();

        options.AllowAnonymousPath(path);

        var root = options.BuildMappingTree(authzOptions);
        var (_, allowAnonymous) = root.GetAuthorizationDataForPath(path);

        Assert.True(allowAnonymous);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_RetainsDefaultPolicy_WhenCallingBothAuthorizePathAndAllowAnonymous(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var options = new PathAuthorizationOptions();

        options.AuthorizePath(path);
        options.AllowAnonymousPath(path);

        var root = options.BuildMappingTree(authzOptions);
        var (policy, allowAnonymous) = root.GetAuthorizationDataForPath(path);

        Assert.Equal(authzOptions.DefaultPolicy, policy);
        Assert.True(allowAnonymous);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_SubPaths_InheritPolicyFromParent(string childPath)
    {
        var authzOptions = new AuthorizationOptions();
        var options = new PathAuthorizationOptions();

        options.AuthorizePath("/parent", p => p.RequireRole("TestRole"));

        var root = options.BuildMappingTree(authzOptions);
        var (parentPolicy, _) = root.GetAuthorizationDataForPath("/parent");
        var (childPolicy, _) = root.GetAuthorizationDataForPath("/parent" + childPath);

        Assert.Equal(parentPolicy, childPolicy);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_SubPaths_InheritAllowAnonymousFromParent(string childPath)
    {
        var authzOptions = new AuthorizationOptions();
        var options = new PathAuthorizationOptions();

        options.AllowAnonymousPath("/parent");

        var root = options.BuildMappingTree(authzOptions);
        var (_, parentAllowAnonymous) = root.GetAuthorizationDataForPath("/parent");
        var (_, childAllowAnonymous) = root.GetAuthorizationDataForPath("/parent" + childPath);

        Assert.Equal(parentAllowAnonymous, childAllowAnonymous);
        Assert.True(childAllowAnonymous);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_SubPaths_InheritAllowAnonymousAndPolicyFromParent(string childPath)
    {
        var authzOptions = new AuthorizationOptions();
        var options = new PathAuthorizationOptions();

        options.AuthorizePath("/parent");
        options.AllowAnonymousPath("/parent");

        var root = options.BuildMappingTree(authzOptions);
        var (parentPolicy, parentAllowAnonymous) = root.GetAuthorizationDataForPath("/parent");
        var (childPolicy, childAllowAnonymous) = root.GetAuthorizationDataForPath("/parent" + childPath);

        Assert.NotNull(parentPolicy);
        Assert.NotNull(childPolicy);
        Assert.Equal(parentPolicy, childPolicy);
        Assert.Equal(parentAllowAnonymous, childAllowAnonymous);
        Assert.True(childAllowAnonymous);
    }

    [Fact]
    public void BuildMappingTree_SubPaths_GetCombinedPolicyFromAncestorsAndSelf()
    {
        var authzOptions = new AuthorizationOptions();
        var options = new PathAuthorizationOptions();

        options.AuthorizePath("/grandparent", p => p.RequireRole("TestRole1"));
        options.AuthorizePath("/grandparent/parent/child", p => p.RequireRole("TestRole2"));

        var root = options.BuildMappingTree(authzOptions);
        var (rootPolicy, _) = root.GetAuthorizationDataForPath("/");
        var (parentPolicy, _) = root.GetAuthorizationDataForPath("/grandparent/parent");
        var (childPolicy, _) = root.GetAuthorizationDataForPath("/grandparent/parent/child");

        Assert.Null(rootPolicy);
        Assert.NotNull(childPolicy);
        Assert.NotNull(parentPolicy);
        Assert.Equal(1, parentPolicy!.Requirements.Count);
        Assert.Equal(2, childPolicy!.Requirements.Count);
    }
}
