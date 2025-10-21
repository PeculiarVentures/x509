import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";
import { themes as prismThemes } from "prism-react-renderer";
import npm2yarn from "@docusaurus/remark-plugin-npm2yarn";
import packageJSON from "../package.json";

const config: Config = {
  title: "@peculiar/x509",
  tagline: "@peculiar/x509",
  favicon: "img/favicon.ico",
  url: "https://peculiarventures.github.io",
  baseUrl: "/x509",
  onBrokenLinks: "throw",
  onBrokenMarkdownLinks: "warn",
  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },
  customFields: {
    description: packageJSON.description,
  },
  presets: [
    [
      "classic",
      {
        docs: {
          path: "docs",
          sidebarPath: "./sidebars.ts",
          remarkPlugins: [npm2yarn],
        },
        theme: {
          customCss: "./src/css/custom.css",
        },
        blog: false,
      } satisfies Preset.Options,
    ],
  ],

  plugins: [
    [
      "docusaurus-plugin-typedoc",
      {
        entryPoints: ["../src/index.ts"],
        tsconfig: "../tsconfig.json",
        skipErrorChecking: true,
        disableSources: true,
        membersWithOwnFile: ["Class", "Enum", "Interface"],
        readme: "none",
        sidebar: {
          pretty: true,
          autoConfiguration: true,
        },
        textContentMappings: {
          "title.memberPage": "{name}",
        },
      },
    ],
    "docusaurus-plugin-sass",
  ],

  themeConfig: {
    prism: {
      theme: prismThemes.oneDark,
    },
    image: "img/card.png",
    colorMode: {
      defaultMode: "light",
      disableSwitch: true,
      respectPrefersColorScheme: false,
    },
    navbar: {
      style: "dark",
      logo: {
        alt: "x509",
        src: "/img/logo.svg",
        width: 80,
      },
      items: [
        {
          type: "docSidebar",
          position: "right",
          sidebarId: "docs",
          label: "Docs",
        },
        {
          href: "https://github.com/PeculiarVentures/x509",
          position: "right",
          className: "header-github-link",
          "aria-label": "GitHub repository",
        },
      ],
    },
    footer: {
      style: "dark",
      copyright: "Made with ❤️ across the globe",
      links: [
        {
          title: "Learn",
          items: [
            {
              label: "Installation",
              to: "/docs/installation",
            },
            {
              label: "Usage",
              to: "/docs/usage",
            },
            {
              label: "API",
              to: "/docs/api",
            },
          ],
        },
        {
          title: "More",
          items: [
            {
              label: "GitHub",
              href: "https://github.com/PeculiarVentures/x509",
            },
            {
              label: "Contact us",
              href: "mailto:info@peculiarventures.com",
            }
          ],
        },
        {
          title: `Version: ${packageJSON.version}`,
        },
      ],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
