const sidebars = {
  docs: [
    "installation",
    "usage",
    {
      type: "category",
      label: "API",
      collapsed: false,
      items: [
        {
          type: "doc",
          id: "api/index",
          label: "Exports",
        },
        ...require("./docs/api/typedoc-sidebar.cjs"),
      ],
    },
  ],
};

export default sidebars;
