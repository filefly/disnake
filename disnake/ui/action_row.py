"""
The MIT License (MIT)

Copyright (c) 2021-present Disnake Development

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
"""

from __future__ import annotations

from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Generator,
    Generic,
    List,
    Literal,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    overload,
)

from ..components import (
    ActionRow as ActionRowComponent,
    Button as ButtonComponent,
    NestedComponent,
    SelectMenu as SelectComponent,
    SelectOption,
)
from ..enums import ButtonStyle, ComponentType, TextInputStyle
from ..utils import MISSING, SequenceProxy
from .button import Button
from .item import WrappedComponent
from .select import Select
from .text_input import TextInput

if TYPE_CHECKING:
    from ..emoji import Emoji
    from ..message import Message
    from ..partial_emoji import PartialEmoji
    from ..types.components import ActionRow as ActionRowPayload

__all__ = (
    "ActionRow",
    "Components",
    "MessageUIComponent",
    "ModalUIComponent",
    "MessageActionRow",
    "ModalActionRow",
)


MessageUIComponent = Union[Button[Any], Select[Any]]
ModalUIComponent = TextInput  # Union[TextInput, Select[Any]]
UIComponentT = TypeVar("UIComponentT", bound=WrappedComponent)
StrictUIComponentT = TypeVar("StrictUIComponentT", MessageUIComponent, ModalUIComponent)

Components = Union[
    "ActionRow[UIComponentT]",
    UIComponentT,
    Sequence[Union["ActionRow[UIComponentT]", UIComponentT, Sequence[UIComponentT]]],
]


class ActionRow(Generic[UIComponentT]):
    """Represents a UI action row. Useful for lower level component manipulation.

    .. container:: operations

        .. describe:: x[i]

            Returns the component at position ``i``.

    To handle interactions created by components sent in action rows or entirely independently,
    event listeners must be used. For buttons and selects, the related events are
    :func:`disnake.on_button_click` and :func:`disnake.on_dropdown`, respectively. Alternatively,
    :func:`disnake.on_message_interaction` can be used for either. For modals, the related event is
    :func:`disnake.on_modal_submit`.

    .. versionadded:: 2.4

    .. versionchanged:: 2.6
        Requires and provides stricter typing for contained components.

    Parameters
    ----------
    *components: :class:`WrappedComponent`
        The components of this action row.

        .. versionchanged:: 2.6
            Components can now be either valid in the context of a message, or in the
            context of a modal. Combining components from both contexts is not supported.
    """

    type: ClassVar[Literal[ComponentType.action_row]] = ComponentType.action_row

    # When unspecified and called empty, default to an ActionRow that takes any kind of component.

    @overload
    def __init__(self: ActionRow[WrappedComponent]):
        ...

    # Explicit definitions are needed to make
    # "ActionRow(Select(), TextInput())" and
    # "ActionRow(Select(), Button())"
    # differentiate themselves properly.

    @overload
    def __init__(self: ActionRow[MessageUIComponent], *components: MessageUIComponent):
        ...

    @overload
    def __init__(self: ActionRow[ModalUIComponent], *components: ModalUIComponent):
        ...

    # Allow use of "ActionRow[StrictUIComponent]" externally.

    @overload
    def __init__(self: ActionRow[StrictUIComponentT], *components: StrictUIComponentT):
        ...

    def __init__(self, *components: UIComponentT):
        self._children: List[UIComponentT] = []

        for component in components:
            if not isinstance(component, WrappedComponent):
                raise TypeError(
                    f"components should be of type WrappedComponent, got {type(component).__name__}."
                )
            self.append_item(component)

    def __repr__(self) -> str:
        return f"<ActionRow children={self._children!r}>"

    def __len__(self) -> int:
        return len(self._children)

    @property
    def children(self) -> Sequence[UIComponentT]:
        """Sequence[:class:`WrappedComponent`]:
        A read-only copy of the UI components stored in this action row. To add/remove
        components to/from the action row, use its methods to directly modify it.

        .. versionchanged:: 2.6
            Returns an immutable sequence instead of a list.
        """
        return SequenceProxy(self._children)

    @property
    def width(self) -> int:
        return sum(child.width for child in self._children)

    def append_item(self, item: UIComponentT) -> None:
        """Append a component to the action row. The component's type must match that
        of the action row.

        Parameters
        ----------
        item: :class:`WrappedComponent`
            The component to append to the action row.

        Raises
        ------
        ValueError
            The width of the action row exceeds 5.
        """
        self.insert_item(len(self), item)

    def insert_item(self, index: int, item: UIComponentT) -> None:
        """Insert a component to the action row at a given index. The component's
        type must match that of the action row.

        .. versionadded:: 2.6

        Parameters
        ----------
        index: :class:`int`
            The index at which to insert the component into the action row.
        item: :class:`WrappedComponent`
            The component to insert into the action row.

        Raises
        ------
        ValueError
            The width of the action row exceeds 5.
        """
        if self.width + item.width > 5:
            raise ValueError("Too many components in this row, can not append a new one.")

        self._children.insert(index, item)

    def add_button(
        self: Union[ActionRow[MessageUIComponent], ActionRow[WrappedComponent]],
        index: Optional[int] = None,
        *,
        style: ButtonStyle = ButtonStyle.secondary,
        label: Optional[str] = None,
        disabled: bool = False,
        custom_id: Optional[str] = None,
        url: Optional[str] = None,
        emoji: Optional[Union[str, Emoji, PartialEmoji]] = None,
    ) -> None:
        """Add a button to the action row. Can only be used if the action
        row holds message components.

        To append a pre-existing :class:`~disnake.ui.Button` use the
        :meth:`append_item` method instead.

        .. versionchanged:: 2.6
            Now allows for inserting at a given index. The default behaviour of
            appending is preserved.

        Parameters
        ----------
        index: :class:`int`
            The index at which to insert the button into the action row. If not provided,
            this method defaults to appending the button to the action row.
        style: :class:`.ButtonStyle`
            The style of the button.
        custom_id: Optional[:class:`str`]
            The ID of the button that gets received during an interaction.
            If this button is for a URL, it does not have a custom ID.
        url: Optional[:class:`str`]
            The URL this button sends you to.
        disabled: :class:`bool`
            Whether the button is disabled or not.
        label: Optional[:class:`str`]
            The label of the button, if any.
        emoji: Optional[Union[:class:`.PartialEmoji`, :class:`.Emoji`, :class:`str`]]
            The emoji of the button, if available.

        Raises
        ------
        ValueError
            The width of the action row exceeds 5.
        """
        self.insert_item(
            len(self) if index is None else index,
            Button(
                style=style,
                label=label,
                disabled=disabled,
                custom_id=custom_id,
                url=url,
                emoji=emoji,
            ),
        )

    def add_select(
        self: Union[
            ActionRow[MessageUIComponent],
            # ActionRow[ModalUIComponent],
            ActionRow[WrappedComponent],
        ],
        *,
        custom_id: str = MISSING,
        placeholder: Optional[str] = None,
        min_values: int = 1,
        max_values: int = 1,
        options: List[SelectOption] = MISSING,
        disabled: bool = False,
    ) -> None:
        """Add a select menu to the action row. Can only be used if the action
        row holds message components.

        To append a pre-existing :class:`~disnake.ui.Select` use the
        :meth:`append_item` method instead.

        Parameters
        ----------
        custom_id: :class:`str`
            The ID of the select menu that gets received during an interaction.
            If not given then one is generated for you.
        placeholder: Optional[:class:`str`]
            The placeholder text that is shown if nothing is selected, if any.
        min_values: :class:`int`
            The minimum number of items that must be chosen for this select menu.
            Defaults to 1 and must be between 1 and 25.
        max_values: :class:`int`
            The maximum number of items that must be chosen for this select menu.
            Defaults to 1 and must be between 1 and 25.
        options: List[:class:`~disnake.SelectOption`]
            A list of options that can be selected in this menu.
        disabled: :class:`bool`
            Whether the select is disabled or not.

        Raises
        ------
        ValueError
            The width of the action row exceeds 5.
        """
        self.append_item(
            Select(
                custom_id=custom_id,
                placeholder=placeholder,
                min_values=min_values,
                max_values=max_values,
                options=options,
                disabled=disabled,
            ),
        )

    def add_text_input(
        self: Union[ActionRow[ModalUIComponent], ActionRow[WrappedComponent]],
        *,
        label: str,
        custom_id: str,
        style: TextInputStyle = TextInputStyle.short,
        placeholder: Optional[str] = None,
        value: Optional[str] = None,
        required: bool = True,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
    ) -> None:
        """Add a text input to the action row. Can only be used if the action
        row holds modal components.

        To append a pre-existing :class:`~disnake.ui.TextInput` use the
        :meth:`append_item` method instead.

        .. versionadded:: 2.4

        Parameters
        ----------
        style: :class:`.TextInputStyle`
            The style of the text input.
        label: :class:`str`
            The label of the text input.
        custom_id: :class:`str`
            The ID of the text input that gets received during an interaction.
        placeholder: Optional[:class:`str`]
            The placeholder text that is shown if nothing is entered.
        value: Optional[:class:`str`]
            The pre-filled value of the text input.
        required: :class:`bool`
            Whether the text input is required. Defaults to ``True``.
        min_length: Optional[:class:`int`]
            The minimum length of the text input.
        max_length: Optional[:class:`int`]
            The maximum length of the text input.

        Raises
        ------
        ValueError
            The width of the action row exceeds 5.
        """
        self.append_item(
            TextInput(
                label=label,
                custom_id=custom_id,
                style=style,
                placeholder=placeholder,
                value=value,
                required=required,
                min_length=min_length,
                max_length=max_length,
            ),
        )

    def clear_items(self) -> None:
        """Remove all components from the action row.

        .. versionadded:: 2.6
        """
        self._children.clear()

    def remove_item(self, item: UIComponentT) -> None:
        """Remove a component from the action row.

        .. versionadded:: 2.6

        Parameters
        ----------
        item: :class:`WrappedComponent`
            The component to remove from the action row.

        Raises
        ------
        ValueError
            The component could not be found on the action row.
        """
        self._children.remove(item)

    def pop(self, index: int) -> UIComponentT:
        """Pop the component at the provided index from the action row.

        .. versionadded:: 2.6

        Parameters
        ----------
        index: :class:`int`
            The index at which to pop the component.

        Raises
        ------
        IndexError
            There is no component at the provided index.
        """
        self.remove_item(component := self[index])
        return component

    @property
    def _underlying(self) -> ActionRowComponent[NestedComponent]:
        return ActionRowComponent._raw_construct(
            type=self.type,
            children=[comp._underlying for comp in self._children],
        )

    def to_component_dict(self) -> ActionRowPayload:
        return self._underlying.to_dict()

    def __delitem__(self, index: int) -> None:
        del self._children[index]

    def __getitem__(self, index: int) -> UIComponentT:
        return self._children[index]

    @classmethod
    def with_modal_components(cls) -> ActionRow[ModalUIComponent]:
        """Create an empty action row meant to store components compatible with
        :class:`disnake.ui.Modal`. Saves the need to import type specifiers to
        typehint empty action rows.

        .. versionadded:: 2.6

        Returns
        -------
        :class:`ActionRow`:
            The newly created empty action row, intended for modal components.
        """
        return ActionRow[ModalUIComponent]()

    @classmethod
    def with_message_components(cls) -> ActionRow[MessageUIComponent]:
        """Create an empty action row meant to store components compatible with
        :class:`disnake.Message`. Saves the need to import type specifiers to
        typehint empty action rows.

        .. versionadded:: 2.6

        Returns
        -------
        :class:`ActionRow`:
            The newly created empty action row, intended for message components.
        """
        return ActionRow[MessageUIComponent]()

    @classmethod
    def rows_from_message(
        cls,
        message: Message,
        *,
        strict: bool = True,
    ) -> List[ActionRow[MessageUIComponent]]:
        """Create a list of up to 5 action rows from the components on an existing message.

        This will abide by existing component format on the message, including component
        ordering and rows. Components will be transformed to UI kit components, such that
        they can be easily modified and re-sent as action rows.

        .. versionadded:: 2.6

        Parameters
        ----------
        message: :class:`disnake.Message`
            The message from which to extract the components.
        strict: :class:`bool`
            Whether or not to raise an exception if an unknown component type is encountered.

        Raises
        ------
        TypeError
            Strict-mode is enabled and an unknown component type is encountered.

        Returns
        -------
        List[:class:`ActionRow`]:
            The action rows parsed from the components on the message.
        """
        rows: List[ActionRow[MessageUIComponent]] = []
        for row in message.components:
            rows.append(current_row := ActionRow.with_message_components())
            for component in row.children:
                if isinstance(component, ButtonComponent):
                    current_row.append_item(Button.from_component(component))
                elif isinstance(component, SelectComponent):
                    current_row.append_item(Select.from_component(component))
                elif strict:
                    raise TypeError(f"Encountered unknown component type: {component.type!r}.")

        return rows

    @staticmethod
    def walk_components(
        action_rows: Sequence[ActionRow[UIComponentT]],
    ) -> Generator[Tuple[ActionRow[UIComponentT], UIComponentT], None, None]:
        """Iterate over the components in a sequence of action rows, yielding each
        individual component together with the action row of which it is a child.

        .. versionadded:: 2.6

        Parameters
        ----------
        action_rows: Sequence[:class:`ActionRow`]
            The sequence of action rows over which to iterate.

        Yields
        ------
        Tuple[:class:`ActionRow`, :class:`WrappedComponent`]
            A tuple containing an action row and a component of that action row.
        """
        for row in tuple(action_rows):
            for component in tuple(row._children):
                yield row, component


MessageActionRow = ActionRow[MessageUIComponent]
ModalActionRow = ActionRow[ModalUIComponent]


def components_to_rows(
    components: Components[StrictUIComponentT],
) -> List[ActionRow[StrictUIComponentT]]:
    if not isinstance(components, Sequence):
        components = [components]

    action_rows: List[ActionRow[StrictUIComponentT]] = []
    auto_row: ActionRow[StrictUIComponentT] = ActionRow[StrictUIComponentT]()

    for component in components:
        if isinstance(component, WrappedComponent):
            try:
                auto_row.append_item(component)
            except ValueError:
                action_rows.append(auto_row)
                auto_row = ActionRow[StrictUIComponentT](component)
        else:
            if auto_row.width > 0:
                action_rows.append(auto_row)
                auto_row = ActionRow[StrictUIComponentT]()

            if isinstance(component, ActionRow):
                action_rows.append(component)

            elif isinstance(component, Sequence):
                action_rows.append(ActionRow[StrictUIComponentT](*component))

            else:
                raise TypeError(
                    "`components` must be a `WrappedComponent` or `ActionRow`, "
                    "a sequence/list of `WrappedComponent`s or `ActionRow`s, "
                    "or a nested sequence/list of `WrappedComponent`s"
                )

    if auto_row.width > 0:
        action_rows.append(auto_row)

    return action_rows


def components_to_dict(components: Components[StrictUIComponentT]) -> List[ActionRowPayload]:
    return [row.to_component_dict() for row in components_to_rows(components)]
