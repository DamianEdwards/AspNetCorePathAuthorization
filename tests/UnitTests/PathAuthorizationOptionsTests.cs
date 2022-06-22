using AspNetCore.Authorization.PathBased;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

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

    [Fact]
    public void BuildMappingTree_CreatesOneNodePerLogicalChild()
    {
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(new AuthorizationOptions()));
        var options = new PathAuthorizationOptions();

        options.AuthorizePath("/");
        options.AuthorizePath("/a");
        options.AuthorizePath("/a/b");
        options.AuthorizePath("/a/c");
        options.AuthorizePath("/a/c/c1");
        options.AuthorizePath("/a/c/c2");
        options.AuthorizePath("/a/c/c3");
        options.AuthorizePath("/d");
        options.AuthorizePath("/e");
        options.AuthorizePath("/f");

        var root = options.BuildMappingTree(policyProvider);
        var a = root.Children["a"];
        var b = a.Children["b"];
        var c = a.Children["c"];

        Assert.Equal(4, root.Children.Count);
        Assert.Equal(2, a.Children.Count);
        Assert.Empty(b.Children);
        Assert.Equal(3, c.Children.Count);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_AppliesDefaultsToPathNotRegisteredForAuthorization(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
        var options = new PathAuthorizationOptions();

        var root = options.BuildMappingTree(policyProvider);
        var (_, policy, allowAnonymous) = root.GetAuthorizeDataForPath(path);

        Assert.Null(policy);
        Assert.Null(allowAnonymous);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_UsesDefaultPolicy(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
        var options = new PathAuthorizationOptions();

        options.AuthorizePath(path);

        var root = options.BuildMappingTree(policyProvider);
        var (_, policy, _) = root.GetAuthorizeDataForPath(path);

        Assert.NotNull(policy);
        Assert.Empty(policy!.AuthenticationSchemes);
        Assert.Single(policy!.Requirements);
    }

#if NET7_0_OR_GREATER
    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_UsesSuppliedPolicyBuilderDelegate(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
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

        var root = options.BuildMappingTree(policyProvider);
        var (_, policy, _) = root.GetAuthorizeDataForPath(path);

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
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
        var options = new PathAuthorizationOptions();
        var policyBuilder = new AuthorizationPolicyBuilder();
        policyBuilder.RequireRole("TestRole");
        var expectedPolicy = policyBuilder.Build();

        options.AuthorizePath(path, expectedPolicy);

        var root = options.BuildMappingTree(policyProvider);
        var (_, policy, _) = root.GetAuthorizeDataForPath(path);

        Assert.NotNull(policy);
        Assert.Equal(expectedPolicy, policy);
    }
#endif

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_UsesSuppliedPolicyName(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
        var policyBuilder = new AuthorizationPolicyBuilder();
        policyBuilder.RequireRole("TestRole");
        var expectedPolicy = policyBuilder.Build();
        authzOptions.AddPolicy("TestPolicy", expectedPolicy);
        var options = new PathAuthorizationOptions();

        options.AuthorizePath(path, "TestPolicy");

        var root = options.BuildMappingTree(policyProvider);
        var (_, policy, _) = root.GetAuthorizeDataForPath(path);

        Assert.NotNull(policy);
        Assert.Equal(expectedPolicy.Requirements.Count, policy!.Requirements.Count);
        Assert.Equal(expectedPolicy.AuthenticationSchemes.Count, policy!.AuthenticationSchemes.Count);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_ThrowsInvalidOperationException_IfSuppliedPolicyNameIsNotDefined(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
        var options = new PathAuthorizationOptions();

        options.AuthorizePath(path, "NonExistentPolicy");

        Assert.Throws<InvalidOperationException>(() =>
        {
            var root = options.BuildMappingTree(policyProvider);
        });
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_SetsAllowAnonymous(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
        var options = new PathAuthorizationOptions();

        options.AllowAnonymousPath(path);

        var root = options.BuildMappingTree(policyProvider);
        var (_, _, allowAnonymous) = root.GetAuthorizeDataForPath(path);

        Assert.True(allowAnonymous);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_RetainsDefaultPolicy_WhenCallingBothAuthorizePathAndAllowAnonymous(string path)
    {
        var authzOptions = new AuthorizationOptions();
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
        var options = new PathAuthorizationOptions();

        options.AuthorizePath(path);
        options.AllowAnonymousPath(path);

        var root = options.BuildMappingTree(policyProvider);
        var (_, policy, allowAnonymous) = root.GetAuthorizeDataForPath(path);

        Assert.NotNull(policy);
        Assert.Empty(policy!.AuthenticationSchemes);
        Assert.Single(policy.Requirements);
        Assert.True(allowAnonymous);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_SubPaths_InheritPolicyFromParent(string childPath)
    {
        var authzOptions = new AuthorizationOptions();
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
        var options = new PathAuthorizationOptions();

        options.AuthorizePathRoles("/parent", "TestRole");

        var root = options.BuildMappingTree(policyProvider);
        var (_, parentPolicy, _) = root.GetAuthorizeDataForPath("/parent");
        var (_, childPolicy, _) = root.GetAuthorizeDataForPath("/parent" + childPath);

        Assert.Equal(parentPolicy, childPolicy);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_SubPaths_InheritAllowAnonymousFromParent(string childPath)
    {
        var authzOptions = new AuthorizationOptions();
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
        var options = new PathAuthorizationOptions();

        options.AllowAnonymousPath("/parent");

        var root = options.BuildMappingTree(policyProvider);
        var (_, _, parentAllowAnonymous) = root.GetAuthorizeDataForPath("/parent");
        var (_, _, childAllowAnonymous) = root.GetAuthorizeDataForPath("/parent" + childPath);

        Assert.Equal(parentAllowAnonymous, childAllowAnonymous);
        Assert.True(childAllowAnonymous);
    }

    [Theory]
    [MemberData(nameof(GetPathList))]
    public void BuildMappingTree_SubPaths_InheritAllowAnonymousAndPolicyFromParent(string childPath)
    {
        var authzOptions = new AuthorizationOptions();
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
        var options = new PathAuthorizationOptions();

        options.AuthorizePath("/parent");
        options.AllowAnonymousPath("/parent");

        var root = options.BuildMappingTree(policyProvider);
        var (_, parentPolicy, parentAllowAnonymous) = root.GetAuthorizeDataForPath("/parent");
        var (_, childPolicy, childAllowAnonymous) = root.GetAuthorizeDataForPath("/parent" + childPath);

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
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
        var options = new PathAuthorizationOptions();

        options.AuthorizePathRoles("/grandparent", "TestRole1");
        options.AuthorizePathRoles("/grandparent/parent/child", "TestRole2");

        var root = options.BuildMappingTree(policyProvider);
        var (_, rootPolicy, _) = root.GetAuthorizeDataForPath("/");
        var (_, parentPolicy, _) = root.GetAuthorizeDataForPath("/grandparent/parent");
        var (_, childPolicy, _) = root.GetAuthorizeDataForPath("/grandparent/parent/child");

        Assert.Null(rootPolicy);
        Assert.NotNull(childPolicy);
        Assert.NotNull(parentPolicy);
        Assert.Equal(1, parentPolicy!.Requirements.Count);
        Assert.Equal(2, childPolicy!.Requirements.Count);
    }

    [Fact]
    public void BuildMappingTree_SubPaths_CanOverridAllowAnonymousFromAncestors()
    {
        var authzOptions = new AuthorizationOptions();
        var policyProvider = new DefaultAuthorizationPolicyProvider(Options.Create(authzOptions));
        var options = new PathAuthorizationOptions();

        options.AuthorizePath("/grandparent");
        options.AllowAnonymousPath("/grandparent/parent/child");

        var root = options.BuildMappingTree(policyProvider);
        var (_, rootPolicy, _) = root.GetAuthorizeDataForPath("/");
        var (_, parentPolicy, _) = root.GetAuthorizeDataForPath("/grandparent/parent");
        var (_, childPolicy, childAllowAnonymous) = root.GetAuthorizeDataForPath("/grandparent/parent/child");

        Assert.Null(rootPolicy);
        Assert.NotNull(parentPolicy);
        Assert.NotNull(childPolicy);
        Assert.True(childAllowAnonymous);
    }
}
