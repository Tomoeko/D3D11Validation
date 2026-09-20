// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using UnityEngine;
using UnityEngine.Rendering;

public sealed class RenderRuntime : MonoBehaviour
{
    [DllImport("d3d11", EntryPoint = "DXBCTraceBegin")]
    static extern uint TraceBegin(uint label);
    [DllImport("d3d11", EntryPoint = "DXBCTraceEnd")]
    static extern uint TraceEnd(uint label);
    [DllImport("validation-observer", EntryPoint = "ValidationObserveTexture", CharSet = CharSet.Unicode)]
    static extern uint ObserveTexture(IntPtr resource, string output);
    static uint interval;
    static bool unhooked;
    static string outputDirectory;

    static string Argument(string name)
    {
        var args = Environment.GetCommandLineArgs();
        string found = null;
        for (int i = 0; i < args.Length; ++i)
            if (args[i] == name)
            {
                if (found != null || i + 1 >= args.Length)
                    throw new Exception("Duplicate or missing argument: " + name);
                found = args[++i];
            }
        if (found == null)
            throw new Exception("Missing argument: " + name);
        return found;
    }
    static string Hash(byte[] bytes)
    {
        using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes))
            .Replace("-", "")
            .ToLowerInvariant();
    }
    static void Record(List<string> report, string key, object raw)
    {
        var value = Convert.ToString(raw, CultureInfo.InvariantCulture);
        if (value.IndexOfAny(new[] { '\t', '\r', '\n' }) >= 0)
            throw new Exception("Invalid report field");
        report.Add(key + "\t" + value);
    }
    static Mesh Quad()
    {
        var mesh = new Mesh();
        mesh.name = "RuntimeCanonicalQuad/v1";
        mesh.vertices = new[] { new Vector3(-1, -1, 0), new Vector3(1, -1, 0), new Vector3(-1, 1, 0),
                                new Vector3(1, 1, 0) };
        mesh.uv = new[] { new Vector2(0, 0), new Vector2(1, 0), new Vector2(0, 1), new Vector2(1, 1) };
        mesh.normals = new[] { Vector3.back, Vector3.back, Vector3.back, Vector3.back };
        mesh.tangents = new[] { new Vector4(1, 0, 0, 1), new Vector4(1, 0, 0, 1), new Vector4(1, 0, 0, 1),
                                new Vector4(1, 0, 0, 1) };
        mesh.colors = new[] { Color.white, Color.white, Color.white, Color.white };
        mesh.SetIndices(new[] { 0, 2, 1, 1, 2, 3 }, MeshTopology.Triangles, 0, false);
        mesh.bounds = new Bounds(Vector3.zero, new Vector3(2, 2, 0));
        mesh.UploadMeshData(true);
        return mesh;
    }
    static byte[] Capture(Material material, Mesh mesh)
    {
        var rt = new RenderTexture(4, 4, 24, RenderTextureFormat.ARGBFloat, RenderTextureReadWrite.Linear);
        rt.name = "RuntimeRGBA32F/v1";
        rt.antiAliasing = 1;
        rt.useMipMap = false;
        rt.autoGenerateMips = false;
        rt.enableRandomWrite = false;
        rt.filterMode = FilterMode.Point;
        rt.wrapMode = TextureWrapMode.Clamp;
        Texture2D readback = null;
        var previous = RenderTexture.active;
        try
        {
            if (!rt.Create() || rt.format != RenderTextureFormat.ARGBFloat)
                throw new Exception("Render target unavailable");
            RenderTexture.active = rt;
            GL.Viewport(new Rect(0, 0, 4, 4));
            GL.Clear(true, true, Color.clear, 1);
            uint label = ++interval;
            if (!unhooked && TraceBegin(label) != 1)
                throw new Exception("Trace interval unavailable");
            GL.PushMatrix();
            try
            {
                GL.LoadIdentity();
                GL.LoadProjectionMatrix(Matrix4x4.identity);
                if (!material.SetPass(0))
                    throw new Exception("SetPass failed");
                Graphics.DrawMeshNow(mesh, Matrix4x4.identity, 0);
            }
            finally
            {
                GL.PopMatrix();
            }
            if (unhooked && ObserveTexture(rt.GetNativeTexturePtr(), outputDirectory) != 1)
                throw new Exception("Native render-target identity unavailable");
            readback = new Texture2D(4, 4, TextureFormat.RGBAFloat, false, true);
            readback.ReadPixels(new Rect(0, 0, 4, 4), 0, 0, false);
            readback.Apply(false, false);
            if (!unhooked && TraceEnd(label) != 1)
                throw new Exception("Trace interval incomplete");
            var bytes = readback.GetRawTextureData();
            if (bytes.Length != 256)
                throw new Exception("Wrong readback length");
            return bytes;
        }
        finally
        {
            RenderTexture.active = previous;
            rt.Release();
            DestroyImmediate(rt);
            if (readback != null)
                DestroyImmediate(readback);
        }
    }
    void Start()
    {
        AssetBundle bundle = null;
        Material material = null;
        Mesh mesh = null;
        try
        {
            string input = Argument("-bundle"), output = Argument("-output"),
                   keyword = Argument("-uv-variant");
            string trace = Argument("-trace");
            if (trace != "on" && trace != "off" && trace != "none")
                throw new Exception("Invalid trace mode");
            unhooked = trace == "none";
            outputDirectory = output;
            int tier = int.Parse(Argument("-tier"), CultureInfo.InvariantCulture);
            if (tier < 0 || tier > 2)
                throw new Exception("Invalid tier");
            Graphics.activeTier = (GraphicsTier)tier;
            if ((int)Graphics.activeTier != tier)
                throw new Exception("Tier selection failed");
            RenderSettings.fog = false;
            RenderSettings.fogMode = FogMode.Linear;
            RenderSettings.fogColor = new Color(0.25f, 0.5f, 0.75f, 1);
            RenderSettings.fogStartDistance = 0;
            RenderSettings.fogEndDistance = 300;
            RenderSettings.fogDensity = 0.01f;
            Shader.SetGlobalColor("unity_FogColor", RenderSettings.fogColor);
            Shader.SetGlobalFloat("unity_FogStart", RenderSettings.fogStartDistance);
            Shader.SetGlobalFloat("unity_FogEnd", RenderSettings.fogEndDistance);
            Shader.SetGlobalFloat("unity_FogDensity", RenderSettings.fogDensity);
            if (keyword != "on" && keyword != "off")
                throw new Exception("Invalid keyword state");
            if (Application.unityVersion != "2021.3.35f1" ||
                SystemInfo.graphicsDeviceType != GraphicsDeviceType.Direct3D11 ||
                QualitySettings.activeColorSpace != ColorSpace.Gamma ||
                GraphicsSettings.currentRenderPipeline != null)
                throw new Exception("Unexpected player profile");
            if (File.Exists(Path.Combine(output, "result.tsv")) ||
                File.Exists(Path.Combine(output, "pixels.bin")))
                throw new Exception("Existing output");
            Directory.CreateDirectory(output);
            var report = new List<string>();
            Record(report, "schema", "dxbc-private-player-draw-domain/v2");
            Record(report, "instrumentation", trace);
            Record(report, "bundle_sha256", Hash(File.ReadAllBytes(input)));
            Record(report, "player_metadata_sha256",
                   Hash(File.ReadAllBytes(Path.Combine(Application.dataPath, "globalgamemanagers"))));
            Record(report, "unity_version", Application.unityVersion);
            Record(report, "backend", SystemInfo.graphicsDeviceType);
            Record(report, "device", SystemInfo.graphicsDeviceName);
            Record(report, "driver", SystemInfo.graphicsDeviceVersion);
            Record(report, "render_threading", SystemInfo.renderingThreadingMode);
            if (SystemInfo.renderingThreadingMode != RenderingThreadingMode.Direct)
                throw new Exception("Direct rendering required");
            Record(report, "fog_enabled", RenderSettings.fog);
            Record(report, "fog_mode", RenderSettings.fogMode);
            using (var stream = new MemoryStream()) using (var writer = new BinaryWriter(stream))
            {
                Color color = Shader.GetGlobalColor("unity_FogColor");
                writer.Write(color.r);
                writer.Write(color.g);
                writer.Write(color.b);
                writer.Write(color.a);
                writer.Write(Shader.GetGlobalFloat("unity_FogStart"));
                writer.Write(Shader.GetGlobalFloat("unity_FogEnd"));
                writer.Write(Shader.GetGlobalFloat("unity_FogDensity"));
                writer.Flush();
                Record(report, "fog_input_float32le",
                       BitConverter.ToString(stream.ToArray()).Replace("-", "").ToLowerInvariant());
            }
            Record(report, "active_tier_enum", (int)Graphics.activeTier);
            Record(report, "color_space", QualitySettings.activeColorSpace);
            bundle = AssetBundle.LoadFromFile(input);
            if (bundle == null)
                throw new Exception("Load bundle failed");
            var names = bundle.GetAllAssetNames();
            if (names.Length != 1)
                throw new Exception("Ambiguous asset mapping");
            var shader = bundle.LoadAsset<Shader>(names[0]);
            if (shader == null || !shader.isSupported)
                throw new Exception("Unsupported shader");
            Record(report, "asset", names[0]);
            Record(report, "shader", shader.name);
            Record(report, "supported", shader.isSupported);
            if (shader.GetPropertyCount() != 0)
                throw new Exception("Fixture requires empty property closure");
            bool found = false;
            foreach (var kw in shader.keywordSpace.keywords)
            {
                Record(report, "keyword_decl", kw.name + ":" + kw.isOverridable);
                if (kw.name == "UV_VARIANT" && kw.isOverridable)
                    found = true;
            }
            if (!found)
                throw new Exception("Global UV_VARIANT keyword missing");
            foreach (var kw in Shader.enabledGlobalKeywords)
                Shader.DisableKeyword(kw.name);
            if (keyword == "on")
                Shader.EnableKeyword("UV_VARIANT");
            material = new Material(shader);
            material.shaderKeywords = new string[0];
            if (material.passCount != 1 || material.GetPassName(0) != "PACKED_UV")
                throw new Exception("Unexpected pass topology");
            Record(report, "pass_count", material.passCount);
            Record(report, "pass_name", material.GetPassName(0));
            Record(report, "uv_variant_enabled", Shader.IsKeywordEnabled("UV_VARIANT"));
            Record(report, "material_keyword_count", material.shaderKeywords.Length);
            Record(report, "mesh", "canonical-quad-position-identity-v1");
            Record(report, "render_target", "4x4-rgba32f-linear-depth24-msaa1");
            mesh = Quad();
            var first = Capture(material, mesh);
            var second = Capture(material, mesh);
            if (Hash(first) != Hash(second))
                throw new Exception("Unstable repeated pixels");
            Record(report, "pixel_bytes", first.Length);
            Record(report, "pixels_sha256", Hash(first));
            Record(report, "repeated_pixels_equal", true);
            Record(report, "set_pass", true);
            File.WriteAllBytes(Path.Combine(output, "pixels.bin"), first);
            File.WriteAllLines(Path.Combine(output, "result.tsv"), report, new UTF8Encoding(false));
            Application.Quit(0);
        }
        catch (Exception e)
        {
            Debug.LogException(e);
            Application.Quit(2);
        }
        finally
        {
            if (material != null)
                DestroyImmediate(material);
            if (mesh != null)
                DestroyImmediate(mesh);
            if (bundle != null)
                bundle.Unload(true);
        }
    }
}
